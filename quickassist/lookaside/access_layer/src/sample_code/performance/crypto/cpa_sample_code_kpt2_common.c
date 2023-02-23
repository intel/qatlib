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
 **************************************************************************/

/***************************************************************************
 * @file cpa_sample_code_kpt2_common.c
 *
 * This file provides some interface for testing key_protection_technology.
 *
 **************************************************************************/
#include "cpa_sample_code_kpt2_common.h"
#if CY_API_VERSION_AT_LEAST(3, 0)

/***************************************************************************
 * @description
 *
 * This function is to load encrypted SWKs to QAT
 *
 * @param[in]  instanceHandle   Instance handle
 * @param[in]  encryptedSWK     encrypted SWK
 * @param[out] kptKeyHandle     keyhandle
 *
 * @detail     load 1 SWK,
 *             and expect the results to be successfully
 *
 * @retval CPA_STATUS_SUCCESS    Load SWK successfully
 * @retval CPA_STATUS_FAIL       Load SWK failed
 *
 ***************************************************************************/
CpaStatus kptLoadSWK(CpaInstanceHandle instanceHandle,
                     CpaCyKptHandle *kptKeyHandle,
                     CpaFlatBuffer *encryptedSWK)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    CpaCyKptLoadKey *pSWKLoadKey = NULL;
    Cpa32U node = 0;
    Cpa32U keyProvisionRetryTimes = 0;

    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get nodeId failed!\n");
        return status;
    }

    pSWKLoadKey =
        qaeMemAllocNUMA(sizeof(CpaCyKptLoadKey), node, BYTE_ALIGNMENT_64);
    if (NULL == pSWKLoadKey)
    {
        return CPA_STATUS_FAIL;
    }
    pSWKLoadKey->wrappingAlgorithm = CPA_CY_KPT_WRAPPING_KEY_TYPE_AES256_GCM;
    pSWKLoadKey->eSWK.pData =
        qaeMemAllocNUMA(encryptedSWK->dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == pSWKLoadKey->eSWK.pData)
    {
        qaeMemFreeNUMA((void **)&pSWKLoadKey);
        return CPA_STATUS_FAIL;
    }
    pSWKLoadKey->eSWK.dataLenInBytes = encryptedSWK->dataLenInBytes;

    memcpy(pSWKLoadKey->eSWK.pData,
           encryptedSWK->pData,
           encryptedSWK->dataLenInBytes);
    do
    {
        status = cpaCyKptLoadKey(
            instanceHandle, pSWKLoadKey, kptKeyHandle, &kptStatus);
        usleep(KEY_PROVISION_RETRY_DELAY_MS * 1000);
        keyProvisionRetryTimes++;
    } while ((CPA_STATUS_RETRY == status) &&
             (keyProvisionRetryTimes <= KEY_PROVISION_RETRY_TIMES_LIMIT));
    if (1 < keyProvisionRetryTimes)
    {
        PRINT("KPT Load Key Retry Times : %d\n", keyProvisionRetryTimes - 1);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_CY_KPT_SUCCESS != kptStatus)
        {
            PRINT_ERR("Check CPA_CY_KPT_SUCCESS failed.\n");
            status = CPA_STATUS_FAIL;
        }
    }
    else
    {
        PRINT_ERR("cpaCyKptLoadKey failed with status:%d.\n", status);
    }

    if (NULL != pSWKLoadKey)
    {
        if (NULL != pSWKLoadKey->eSWK.pData)
        {
            qaeMemFreeNUMA((void **)&pSWKLoadKey->eSWK.pData);
        }
        qaeMemFreeNUMA((void **)&pSWKLoadKey);
    }

    return status;
}
EXPORT_SYMBOL(kptLoadSWK);

/***************************************************************************
 * @description
 *
 * This function is to encrypt SWKs.
 *
 * @param[in]  instanceHandle               Instance Handle
 * @param[in]  sampleSWK                    SWK
 * @param[out] encryptedSWK                 encrypted SWK
 *
 * @retval CPA_STATUS_SUCCESS    Setup successfully
 * @retval CPA_STATUS_FAIL       Setup failed
 ***************************************************************************/
CpaStatus kptEncryptSWK(CpaInstanceHandle instanceHandle,
                        Cpa8U *sampleSWK,
                        CpaFlatBuffer **encryptedSWK)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaCyKptValidationKey *pPerPartPublicKeyData = NULL;
    EVP_PKEY *pPubKey = NULL;
    EVP_PKEY_CTX *pCtx = NULL;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    BN_CTX *pBn_ctx = NULL;
    OSSL_PARAM_BLD *pBld = NULL;
    BIGNUM *pE_bn = NULL;
    BIGNUM *pN_bn = NULL;
    OSSL_PARAM *pParams = NULL;
#else
    CpaBoolean retStatus = CPA_TRUE;
    RSA *pKey = NULL;
#endif

    int ret = 0;
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;
    Cpa32U node = 0;
    Cpa32U keyProvisionRetryTimes = 0;

    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Get node ID failed!\n");
        return status;
    }

    pPerPartPublicKeyData =
        qaeMemAllocNUMA(sizeof(CpaCyKptValidationKey), node, BYTE_ALIGNMENT_64);
    if (NULL == pPerPartPublicKeyData)
    {
        status = CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*get I-PuK*/
        pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes =
            CPA_CY_RSA3K_SIG_SIZE_INBYTES;
        pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes =
            PER_PART_PKEY_E_SIZE;
        pPerPartPublicKeyData->publicKey.modulusN.pData =
            qaeMemAllocNUMA(sizeof(Cpa8U) * CPA_CY_RSA3K_SIG_SIZE_INBYTES,
                            node,
                            BYTE_ALIGNMENT_64);
        pPerPartPublicKeyData->publicKey.publicExponentE.pData =
            qaeMemAllocNUMA(
                sizeof(Cpa8U) * PER_PART_PKEY_E_SIZE, node, BYTE_ALIGNMENT_64);
        if ((NULL == pPerPartPublicKeyData->publicKey.modulusN.pData) ||
            (NULL == pPerPartPublicKeyData->publicKey.publicExponentE.pData))
        {
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        do
        {
            status = cpaCyKptQueryDeviceCredentials(
                instanceHandle, pPerPartPublicKeyData, &kptStatus);
            usleep(KEY_PROVISION_RETRY_DELAY_MS * 1000);
            keyProvisionRetryTimes++;
        } while ((CPA_STATUS_RETRY == status) &&
                 (keyProvisionRetryTimes <= KEY_PROVISION_RETRY_TIMES_LIMIT));
        if (1 < keyProvisionRetryTimes)
        {
            PRINT("KPT Get I-Pu Retry Times : %d\n",
                  keyProvisionRetryTimes - 1);
        }
        if (CPA_STATUS_SUCCESS != status || CPA_CY_KPT_SUCCESS != kptStatus)
        {
            PRINT_ERR("Get I-Pu failed with status: %d,kptStatus: %d\n",
                      status,
                      kptStatus);
            status = CPA_STATUS_FAIL;
        }
    }
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (CPA_STATUS_SUCCESS == status)
    {
        pBn_ctx = BN_CTX_new();
        pBld = OSSL_PARAM_BLD_new();
        if ((NULL == pBn_ctx) || (NULL == pBld))
        {
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pN_bn = BN_CTX_get(pBn_ctx);
        pE_bn = BN_CTX_get(pBn_ctx);
        if ((NULL == pN_bn) || (NULL == pE_bn))
        {
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        BN_bin2bn(pPerPartPublicKeyData->publicKey.modulusN.pData,
                  pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes,
                  pN_bn);
        OSSL_PARAM_BLD_push_BN(pBld, "n", pN_bn);

        BN_bin2bn(
            pPerPartPublicKeyData->publicKey.publicExponentE.pData,
            pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes,
            pE_bn);
        OSSL_PARAM_BLD_push_BN(pBld, "e", pE_bn);

        pParams = OSSL_PARAM_BLD_to_param(pBld);
        if (NULL == pParams)
        {
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pCtx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates generate key context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        EVP_PKEY_fromdata_init(pCtx);
        EVP_PKEY_fromdata(pCtx, &pPubKey, EVP_PKEY_PUBLIC_KEY, pParams);
        EVP_PKEY_CTX_free(pCtx);

        pCtx = EVP_PKEY_CTX_new(pPubKey, NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
#else
    if (CPA_STATUS_SUCCESS == status)
    {
        pKey = RSA_new();
        pPubKey = EVP_PKEY_new();
        if (NULL == pKey)
        {
            status = CPA_STATUS_FAIL;
        }
        else if (NULL == pPubKey)
        {
            RSA_free(pKey);
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*-----set public key with n and e-----*/
        retStatus = RSA_set0_key(
            pKey,
            BN_bin2bn(pPerPartPublicKeyData->publicKey.modulusN.pData,
                      pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes,
                      NULL),
            BN_bin2bn(
                pPerPartPublicKeyData->publicKey.publicExponentE.pData,
                pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes,
                NULL),
            NULL);
        if (CPA_TRUE != retStatus)
        {
            PRINT_ERR("RSA_set0_key failed \n");
            RSA_free(pKey);
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        EVP_PKEY_assign_RSA(pPubKey, pKey);
        pCtx = EVP_PKEY_CTX_new(pPubKey, NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
#endif // #if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (CPA_STATUS_SUCCESS == status)
    {
        if (EVP_PKEY_encrypt_init(pCtx) > 0)
        {
            EVP_PKEY_CTX_ctrl_str(pCtx, "rsa_padding_mode", "oaep");
            EVP_PKEY_CTX_ctrl_str(pCtx, "rsa_oaep_md", "sha256");
            EVP_PKEY_CTX_ctrl_str(pCtx, "rsa_mgf1_md", "sha256");
        }
        else
        {
            PRINT_ERR("Initializes a public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*encrypt SWK*/
        (*encryptedSWK)->pData = qaeMemAlloc(
            pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes +
            pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes);
        if (NULL == (*encryptedSWK)->pData)
        {
            PRINT_ERR("qaeMemAlloc error\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        (*encryptedSWK)->dataLenInBytes =
            pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes +
            pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes;

        ret = EVP_PKEY_encrypt(pCtx,
                               (*encryptedSWK)->pData,
                               (size_t *)&((*encryptedSWK)->dataLenInBytes),
                               sampleSWK,
                               SWK_LEN_IN_BYTES);
        if ((ret <= 0) || (0 == (*encryptedSWK)->dataLenInBytes) ||
            ((*encryptedSWK)->dataLenInBytes >
             (pPerPartPublicKeyData->publicKey.modulusN.dataLenInBytes +
              pPerPartPublicKeyData->publicKey.publicExponentE.dataLenInBytes)))
        {
            PRINT_ERR("Encrypt SWK failed!\n");
            qaeMemFree((void **)&((*encryptedSWK)->pData));
            status = CPA_STATUS_FAIL;
        }
    }

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (NULL != pBn_ctx)
    {
        BN_CTX_free(pBn_ctx);
    }
    if (NULL != pBld)
    {
        OSSL_PARAM_BLD_free(pBld);
    }
    if (NULL != pParams)
    {
        OSSL_PARAM_free(pParams);
    }
#endif
    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
    if (NULL != pPubKey)
    {
        EVP_PKEY_free(pPubKey);
    }
    if (NULL != pPerPartPublicKeyData)
    {
        if (NULL != pPerPartPublicKeyData->publicKey.modulusN.pData)
        {
            qaeMemFreeNUMA(
                (void **)&pPerPartPublicKeyData->publicKey.modulusN.pData);
        }
        if (NULL != pPerPartPublicKeyData->publicKey.publicExponentE.pData)
        {
            qaeMemFreeNUMA((void **)&pPerPartPublicKeyData->publicKey
                               .publicExponentE.pData);
        }
        qaeMemFreeNUMA((void **)&pPerPartPublicKeyData);
    }
    return status;
}
EXPORT_SYMBOL(kptEncryptSWK);

/***************************************************************************
 * @description
 *
 * This function is to encrypt SWKs and load encrypted SWK to QAT
 *
 * @param[in]  instanceHandle   Instance handle
 * @param[in]  sampleSWK        SWK
 * @param[out] kptKeyHandle     key handle
 *
 * @detail     Encrypt and load 1 SWK,
 *             and expect the results to be SC_LOAD_SWK_SUCCESS
 *
 * @retval CPA_STATUS_SUCCESS    Load SWK successfully
 * @retval CPA_STATUS_FAIL       Load SWK failed
 *
 ***************************************************************************/
CpaStatus encryptAndLoadSWK(CpaInstanceHandle instanceHandle,
                            CpaCyKptHandle *kptKeyHandle,
                            Cpa8U *sampleSWK)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer *encryptedSWK = NULL;
    /*encrypt SWK*/
    encryptedSWK = qaeMemAlloc(sizeof(CpaFlatBuffer));
    if (NULL == encryptedSWK)
    {
        PRINT_ERR("qaeMemAlloc error\n");
        status = CPA_STATUS_FAIL;
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        status = kptEncryptSWK(instanceHandle, sampleSWK, &encryptedSWK);
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*Load SWKs*/
        status = kptLoadSWK(instanceHandle, kptKeyHandle, encryptedSWK);
    }

    if (NULL != encryptedSWK)
    {
        qaeMemFree((void **)&encryptedSWK);
    }

    return status;
}
EXPORT_SYMBOL(encryptAndLoadSWK);

/***************************************************************************
 * @description
 *
 * This function is to encrypt customer private key by AES-256-GCM
 *
 * @param[in]  pPrivateKey            customer private key
 * @param[in]  privateKeyLength       customer private key length
 * @param[in]  pSWK                   SWK
 * @param[in]  pIv                    iv
 * @param[in]  ivLength               iv length
 * @param[in]  pAad                   Additional Authenticated Data
 * @param[in]  aadLenInBytes          the length of aad
 * @param[out] pWrappedPrivateKey     wrapped private key
 * @param[out] pWPKLenth              wrapped private key length
 * @param[out] pAuthTag               Authentication tag (16 Bytes)
 *
 * @retval 1    Operation is successful
 * @retval 0    Operation is failure
 ***************************************************************************/
CpaBoolean encryptPrivateKey(Cpa8U *pPrivateKey,
                             Cpa32U privateKeyLength,
                             Cpa8U *pSWK,
                             Cpa8U *pIv,
                             Cpa32U ivLength,
                             Cpa8U *pWrappedPrivateKey,
                             Cpa32U *pWPKLenth,
                             Cpa8U *pAuthTag,
                             Cpa8U *pAad,
                             Cpa32U aadLenInBytes)
{
    EVP_CIPHER_CTX *pCtx;
    Cpa32U outputLength;
    Cpa32U cipherTestLen;
    CpaBoolean status = CPA_TRUE;

    if (!(pCtx = EVP_CIPHER_CTX_new()))
    {
        PRINT_ERR("EVP_CIPHER_CTX_new() failed\n");
        return CPA_FALSE;
    }

    if (EVP_EncryptInit_ex(pCtx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 0)
    {
        PRINT_ERR("EVP_EncryptInit_ex() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    if (EVP_CIPHER_CTX_ctrl(pCtx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL) == 0)
    {
        PRINT_ERR("EVP_CIPHER_CTX_ctrl() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    if (EVP_EncryptInit_ex(pCtx, NULL, NULL, pSWK, pIv) == 0)
    {
        PRINT_ERR("EVP_EncryptInit_ex() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    if (EVP_EncryptUpdate(
            pCtx, NULL, (int *)&outputLength, pAad, aadLenInBytes) == 0)
    {
        PRINT_ERR("EVP_EncryptUpdate() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    if (EVP_EncryptUpdate(pCtx,
                          pWrappedPrivateKey,
                          (int *)&outputLength,
                          pPrivateKey,
                          privateKeyLength) == 0)
    {
        PRINT_ERR("EVP_EncryptUpdate() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }
    cipherTestLen = outputLength;

    if (EVP_EncryptFinal_ex(
            pCtx, pWrappedPrivateKey + outputLength, (int *)&outputLength) == 0)
    {
        PRINT_ERR("EVP_EncryptFinal_ex() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    if (EVP_CIPHER_CTX_ctrl(
            pCtx, EVP_CTRL_GCM_GET_TAG, AUTH_TAG_LEN_IN_BYTES, pAuthTag) == 0)
    {
        PRINT_ERR("EVP_CIPHER_CTX_ctrl() failed\n");
        EVP_CIPHER_CTX_free(pCtx);
        return CPA_FALSE;
    }

    EVP_CIPHER_CTX_free(pCtx);

    cipherTestLen += outputLength;
    *pWPKLenth = cipherTestLen;

    return status;
}
EXPORT_SYMBOL(encryptPrivateKey);

#endif /* CY_API_VERSION_AT_LEAST(3, 0) */
