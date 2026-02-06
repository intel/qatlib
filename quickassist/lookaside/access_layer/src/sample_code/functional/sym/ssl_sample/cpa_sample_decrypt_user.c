/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#include "cpa.h"
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/* *************************************************************
 *
 * On core crypto for SSL decrypt
 *
 * ************************************************************* */

CpaStatus sampleCodeAesCbcDecrypt(Cpa8U *pKey,
                                  Cpa32U keyLen,
                                  Cpa8U *pIv,
                                  Cpa8U *pIn,
                                  Cpa8U *pOut)
{

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    int len;
    if ((!pIn) || (!pIv) || (!pKey))
        return CPA_STATUS_FAIL;

    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return CPA_STATUS_FAIL;
    }

    /* Set algorithm for decryption */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL))
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    /* Setting Initialization Vector length */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    /* Initializing key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, pKey, pIv))
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    /*no padding */
    if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    /* Decrypt the message to the output buffer */
    if (!EVP_DecryptUpdate(ctx, pOut, &len, pIn, 16))
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }

    /* Free the cipher context */
    EVP_CIPHER_CTX_free(ctx);
    return CPA_STATUS_SUCCESS;
exit:
    EVP_CIPHER_CTX_free(ctx);
    return CPA_STATUS_FAIL;
#else
    AES_KEY dec_key;
    int i = 0;
    int status = AES_set_decrypt_key(pKey, keyLen << 3, &dec_key);
    if (status == -1)
    {
        return CPA_STATUS_FAIL;
    }
    AES_decrypt(pIn, pOut, &dec_key);

    /* Xor with IV */
    for (i = 0; i < 16; i++)
    {
        pOut[i] = pOut[i] ^ pIv[i];
    }
    return CPA_STATUS_SUCCESS;
#endif
}
