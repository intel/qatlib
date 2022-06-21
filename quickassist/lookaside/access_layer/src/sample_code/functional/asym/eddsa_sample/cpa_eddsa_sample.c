/**
 *****************************************************************************
 *
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
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file cpa_eddsa_sample.c
 *
 * @description
 *     This file contains functions that performs EDDSA operation.
 *     Sample represents HashEdDSA on Edwards 25519 curve described
 *     in RFC 8032. (https://tools.ietf.org/html/rfc8032)
 *
 *****************************************************************************/

#include "cpa_eddsa_sample.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

extern int gDebugParam;
CpaInstanceHandle cyInstHandle; /* Instance handle used in point multiply */

/* Order of Edwards 25519 curve */
static Cpa8U order[32] = {0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
                          0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

/* Base point X coordinate of Edwards 25519 curve */
static Cpa8U Bx[32] = {0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9,
                       0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
                       0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0,
                       0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21};

/* Base point Y coordinate of Edwards 25519 curve */
static Cpa8U By[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                       0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

/*****************************************************************************
 * @description
 *     This function reduces scalar to field order value
 *
 * @param[in]  fb  Pointer to flat buffer with scalar value
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus reduceScalar(CpaFlatBuffer *fb)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer L = {0};
    Cpa8U *data = NULL;

    /* Prepare L value flat buffer */
    if (CPA_STATUS_SUCCESS == status)
        status = copyToFlatBuffer(&L, order, sizeof(order));

    /* Reduce fb % L */
    if (CPA_STATUS_SUCCESS == status)
        status = bigNumMod(fb, fb, &L);

    /* Align output buffer to DATA_LEN for QAT operations */
    if (CPA_STATUS_SUCCESS == status && fb->dataLenInBytes < DATA_LEN)
    {
        status = OS_MALLOC(&data, DATA_LEN);
        if (CPA_STATUS_SUCCESS == status)
        {
            memset(data, 0, DATA_LEN);
            memcpy(data, fb->pData, fb->dataLenInBytes);
            OS_FREE(fb->pData);
            fb->pData = data;
            fb->dataLenInBytes = DATA_LEN;
        }
    }

    /* Free memory */
    OS_FREE(L.pData);

    return status;
}

void memcpy_reverse(Cpa8U *dest, Cpa8U *src, Cpa32U src_len)
{
    Cpa32U i = 0;
    Cpa32U j = 0;

    for (i = 0, j = src_len - 1; 0 < j + 1; j--, i++)
        dest[i] = src[j];
}

CpaStatus copyToFlatBuffer(CpaFlatBuffer *fb, Cpa8U *input, Cpa32U inputLen)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (fb->pData != NULL)
    {
        OS_FREE(fb->pData);
        fb->pData = NULL;
    }

    status = OS_MALLOC(&fb->pData, inputLen);
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("Memory alloc error\n");

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(fb->pData, input, inputLen);
        fb->dataLenInBytes = inputLen;
    }

    return status;
}

/*****************************************************************************
 * @description
 *     This function performs scalar multiplication of a point on Edwards 25519
 *     curve.
 *
 * @param[in]   pPointX     Pointer to buffer with X coordinate in little endian
 *                          integer
 * @param[in]   pPointY     Pointer to buffer with Y coordinate in little endian
 *                          integer
 * @param[in]   pScalar     Pointer to buffer with scalar in little endian
 *                          integer
 *
 * @param[out]  pGenPointX  Pointer to buffer with X coordinate of multiplied
 *                          point in little endian integer
 * @param[out]  pGenPointY  Pointer to buffer with Y coordinate of multiplied
 *                          point in little endian integer
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus pointMuliplication(Cpa8U *pPointX,
                                    Cpa8U *pPointY,
                                    Cpa8U *pScalar,
                                    Cpa8U *pGenPointX,
                                    Cpa8U *pGenPointY)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean multiplyStatus = CPA_TRUE;
    CpaCyEcMontEdwdsPointMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pGenX = NULL;
    CpaFlatBuffer *pGenY = NULL;

    /* Allocate output flat buffers */
    status = OS_MALLOC(&pGenX, sizeof(CpaFlatBuffer));
    status |= OS_MALLOC(&pGenY, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("Memory alloc error\n");
    else
    {
        pGenY->dataLenInBytes = DATA_LEN;
        pGenX->dataLenInBytes = DATA_LEN;
    }

    /* Alloc data for output buffers */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pGenX->pData, pGenX->dataLenInBytes, BYTE_ALIGNMENT_64);
        status |= PHYS_CONTIG_ALLOC_ALIGNED(
            &pGenY->pData, pGenY->dataLenInBytes, BYTE_ALIGNMENT_64);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Alloc and setup opData */
    if (CPA_STATUS_SUCCESS == status)
    {
        status =
            OS_MALLOC(&pOpData, sizeof(CpaCyEcMontEdwdsPointMultiplyOpData));
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
        else
        {
            pOpData->generator = CPA_FALSE;
            pOpData->curveType = CPA_CY_EC_MONTEDWDS_ED25519_TYPE;
            pOpData->x.dataLenInBytes = DATA_LEN;
            pOpData->y.dataLenInBytes = DATA_LEN;
            pOpData->k.dataLenInBytes = DATA_LEN;
        }
    }

    /* Alloc x y k buffers and copy x y k values */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData->x.pData, pOpData->x.dataLenInBytes, BYTE_ALIGNMENT_64);
        status |= PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData->y.pData, pOpData->y.dataLenInBytes, BYTE_ALIGNMENT_64);
        status |= PHYS_CONTIG_ALLOC_ALIGNED(
            &pOpData->k.pData, pOpData->k.dataLenInBytes, BYTE_ALIGNMENT_64);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
        else
        {
            memcpy_reverse(pOpData->x.pData, pPointX, DATA_LEN);
            memcpy_reverse(pOpData->y.pData, pPointY, DATA_LEN);
            memcpy_reverse(pOpData->k.pData, pScalar, DATA_LEN);
        }
    }

    /* Perform point multiply */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaCyEcMontEdwdsPointMultiply\n");
        status = cpaCyEcMontEdwdsPointMultiply(
            cyInstHandle, NULL, NULL, pOpData, &multiplyStatus, pGenX, pGenY);
    }

    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("cpaCyEcMontEdwdsPointMultiply failed. (status = %d)\n",
                  status);

    /* Copy point to output buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy_reverse(pGenPointX, pGenX->pData, pGenX->dataLenInBytes);
        memcpy_reverse(pGenPointY, pGenY->pData, pGenY->dataLenInBytes);
    }

    /* Free memory */
    PHYS_CONTIG_FREE(pOpData->x.pData);
    PHYS_CONTIG_FREE(pOpData->y.pData);
    PHYS_CONTIG_FREE(pOpData->k.pData);
    PHYS_CONTIG_FREE(pGenX->pData);
    PHYS_CONTIG_FREE(pGenY->pData);
    OS_FREE(pOpData);
    OS_FREE(pGenX);
    OS_FREE(pGenY);

    return status;
}

/*****************************************************************************
 * @description
 *     This function performs public key generation for EdDSA.
 *
 * @param[in]   privateKey  Pointer to buffer with private key
 *
 * @param[out]  publicKey   Pointer to buffer with generated public key
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus edDsaGenPubKey(Cpa8U *privateKey, Cpa8U *publicKey)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa8U s[HASH_LEN] = {0};
    Cpa8U publicKeyX[DATA_LEN] = {0};
    Cpa8U publicKeyY[DATA_LEN] = {0};

    PRINT_DBG("Generate public key\n");

    /* Hash the 32-byte private key using SHA-512, storing the digest in
       a 64-octet large buffer */
    status = osalHashSHA512Full(privateKey, s, DATA_LEN);

    /* Prune the buffer: The lowest three bits of the first octet are
     * cleared, the highest bit of the last octet is cleared, and the
     * second highest bit of the last octet is set */
    if (CPA_STATUS_SUCCESS == status)
    {
        CLR_BIT(s[0], 0);
        CLR_BIT(s[0], 1);
        CLR_BIT(s[0], 2);
        SET_BIT(s[DATA_LEN - 1], 6);
        CLR_BIT(s[DATA_LEN - 1], 7);

        /* Perform a fixed-base scalar multiplication [s]B */
        status = pointMuliplication(Bx, By, s, publicKeyX, publicKeyY);
    }

    /* The public key A is the encoding of the point [s]B. */
    if (CPA_STATUS_SUCCESS == status)
        encodePoint(publicKeyX, publicKeyY, publicKey);

    return status;
}

/*****************************************************************************
 * @description
 *     This function performs sign operation on HashEdDSA algorithm using
 *     Edwards 25519 curve.
 *
 * @param[in]   privateKey   Pointer to buffer with private key
 * @param[in]   messageHash  Pointer to buffer with hash from a message to sign
 *
 * @param[out]  signature    Pointer to buffer with generated signature
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus edDsaSign(Cpa8U *privateKey,
                           Cpa8U *messageHash,
                           Cpa8U *signature)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa8U *dataToHash = NULL;  /* Pointer to memory used in hash function */
    CpaFlatBuffer L = {0};     /* Flat buffer to store field order value */
    Cpa8U *PH_M = messageHash; /* Message hash (sha512) */
    Cpa8U h[HASH_LEN] = {0};   /* Hash calculated from private key */
    Cpa8U *prefix = 0;         /* Pointer to prefix value */
    CpaFlatBuffer k = {0};     /* Flat buffer to store k scalar value */
    CpaFlatBuffer r = {0};     /* Flat buffer to store r scalar value */
    CpaFlatBuffer s = {0};     /* Flat buffer to store s scalar value */
    Cpa8U Ax[DATA_LEN] = {0};  /* A point X coordinate value */
    Cpa8U Ay[DATA_LEN] = {0};  /* A point Y coordinate value */
    Cpa8U A[DATA_LEN] = {0};   /* Encoded A point value */
    Cpa8U Rx[DATA_LEN] = {0};  /* R point X coordinate value */
    Cpa8U Ry[DATA_LEN] = {0};  /* R point Y coordinate value */
    Cpa8U R[DATA_LEN] = {0};   /* Encoded R point value */
    CpaFlatBuffer S = {0};     /* S signature value */

    PRINT_DBG("Generate signature\n");

    /* Hash the 32-byte private key using SHA-512, storing the digest in
       a 64-octet large buffer */
    status = osalHashSHA512Full(privateKey, h, DATA_LEN);

    /* s scalar is first part of h */
    if (CPA_STATUS_SUCCESS == status)
        status = copyToFlatBuffer(&s, h, DATA_LEN);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Prune the buffer: The lowest three bits of the first octet are
         * cleared, the highest bit of the last octet is cleared, and the
         * second highest bit of the last octet is set */
        CLR_BIT(s.pData[0], 0);
        CLR_BIT(s.pData[0], 1);
        CLR_BIT(s.pData[0], 2);
        SET_BIT(s.pData[DATA_LEN - 1], 6);
        CLR_BIT(s.pData[DATA_LEN - 1], 7);

        /* Perform a fixed-base scalar multiplication [s]B */
        status = pointMuliplication(Bx, By, s.pData, Ax, Ay);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* A is the encoding of the point [s]B. */
        encodePoint(Ax, Ay, A);

        /* Let prefix denote the second half of the hash digest */
        prefix = h + DATA_LEN;

        /* Alloc buffer for hash operation */
        status = OS_MALLOC(&dataToHash, DATA_LEN + HASH_LEN);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Compute SHA-512(prefix || PH(M)), where M is the message to be signed.
     * Interpret the 64-octet digest as a little-endian integer r. */

    /* Copy data to buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(dataToHash, prefix, DATA_LEN);
        memcpy(dataToHash + DATA_LEN, PH_M, HASH_LEN);

        /* Alloc data for output */
        r.dataLenInBytes = HASH_LEN;
        status = OS_MALLOC(&r.pData, r.dataLenInBytes);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Generate r scalar by performing hash operation */
    if (CPA_STATUS_SUCCESS == status)
        status = osalHashSHA512Full(dataToHash, r.pData, DATA_LEN + HASH_LEN);

    /* Reduce r % L (field order) */
    if (CPA_STATUS_SUCCESS == status)
        status = reduceScalar(&r);

    /* Compute the point [r]B. */
    if (CPA_STATUS_SUCCESS == status)
        status = pointMuliplication(Bx, By, r.pData, Rx, Ry);

    /* Let the R be the encoding of this point. */
    if (CPA_STATUS_SUCCESS == status)
        encodePoint(Rx, Ry, R);

    /* Compute SHA512(R || A || PH(M)), and interpret the 64-octet
     * digest as a little-endian integer k. */
    if (CPA_STATUS_SUCCESS == status)
    {
        OS_FREE(dataToHash);
        status = OS_MALLOC(&dataToHash, sizeof(R) + sizeof(A) + HASH_LEN);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Copy R, A, PH_M to buffer for hash operation */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(dataToHash, R, sizeof(R));
        memcpy(dataToHash + sizeof(R), A, sizeof(A));
        memcpy(dataToHash + sizeof(R) + sizeof(A), PH_M, HASH_LEN);

        k.dataLenInBytes = HASH_LEN;
        status = OS_MALLOC(&k.pData, k.dataLenInBytes);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Generate k scalar by performing hash operation */
    if (CPA_STATUS_SUCCESS == status)
        status = osalHashSHA512Full(
            dataToHash, k.pData, sizeof(R) + sizeof(A) + HASH_LEN);

    /* Reduce k % L (field order) */
    if (CPA_STATUS_SUCCESS == status)
        status = reduceScalar(&k);

    /* Compute S = (r + k * s) % L. */
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Prepare L value */
        status = copyToFlatBuffer(&L, order, sizeof(order));

        if (CPA_STATUS_SUCCESS == status)
        {
            status = bigNumModMul(&S, &k, &s, &L);  /* S = k * s % L */
            status |= bigNumModAdd(&S, &S, &r, &L); /* S = S + r % L */
        }
    }

    /* Form the signature of the concatenation of R (32 octets) and the
     * little-endian encoding of S (32 octets; the three most significant bits
     * of the final octet are always zero). */

    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(signature, R, sizeof(R));
        memcpy(signature + DATA_LEN, S.pData, S.dataLenInBytes);
    }

    /* Free memory */
    OS_FREE(dataToHash);
    OS_FREE(L.pData);
    OS_FREE(S.pData);
    OS_FREE(k.pData);
    OS_FREE(r.pData);
    OS_FREE(s.pData);

    return status;
}

/*****************************************************************************
 * @description
 *     This function performs verification of HashEdDSA signature
 *     on Edwards 25519 curve.
 *
 * @param[in]  publicKey    Pointer to buffer with public key
 * @param[in]  messageHash  Pointer to buffer with hash from signed message
 * @param[in]  signature    Pointer to buffer with message signature
 *
 * @retval CPA_STATUS_SUCCESS       Signature verification passed
 * @retval CPA_STATUS_FAIL          Signature verification failed
 *
 *****************************************************************************/
static CpaStatus edDsaVerify(Cpa8U *publicKey,
                             Cpa8U *messageHash,
                             Cpa8U *signature)
{

    CpaStatus status = CPA_STATUS_FAIL;
    Cpa8U *dataToHash = NULL;        /* Pointer to data used in hash function */
    CpaFlatBuffer k = {0};           /* Flat buffer to store k scalar value */
    Cpa8U *PH_M = messageHash;       /* Hash form message (sha512) */
    Cpa8U *S = signature + DATA_LEN; /* S signature scalar value */
    Cpa8U *R = signature;            /* Encoded R point value */
    Cpa8U *A = publicKey;            /* Encoded A point value */
    Cpa8U Ax[DATA_LEN] = {0};        /* A point X coordinate value */
    Cpa8U Ay[DATA_LEN] = {0};        /* A point Y coordinate value */
    Cpa8U Rx[DATA_LEN] = {0};        /* R point X coordinate value */
    Cpa8U Ry[DATA_LEN] = {0};        /* R point Y coordinate value */
    Cpa8U V1x[DATA_LEN] = {0}; /* Verification point 1 X coordinate value */
    Cpa8U V1y[DATA_LEN] = {0}; /* Verification point 1 Y coordinate value */
    Cpa8U V2x[DATA_LEN] = {0}; /* Verification point 2 X coordinate value */
    Cpa8U V2y[DATA_LEN] = {0}; /* Verification point 2 Y coordinate value */

    PRINT_DBG("Verify signature\n");

    /* Split the signature into two 32-octet halfes. Decode the first half as a
     * point R, and the second half as an integer S, in the range 0 <= s < L.
     * Decode the public key A */

    /* Decode R point */
    status = decodePoint(R, Rx, Ry);

    /* Decode A point */
    if (CPA_STATUS_SUCCESS == status)
        status = decodePoint(A, Ax, Ay);

    /* Compute SHA512(R || A || PH(M)), and interpret the 64-octet digest as a
     * little-endian integer k. */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = OS_MALLOC(&dataToHash, (DATA_LEN * 2) + HASH_LEN);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Copy data for hash function */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(dataToHash, R, DATA_LEN);
        memcpy(dataToHash + DATA_LEN, A, DATA_LEN);
        memcpy(dataToHash + (DATA_LEN * 2), PH_M, HASH_LEN);

        /* Alloc output buffer */
        k.dataLenInBytes = HASH_LEN;
        status = OS_MALLOC(&k.pData, k.dataLenInBytes);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Memory alloc error\n");
    }

    /* Generate k scalar by performing hash operation */
    if (CPA_STATUS_SUCCESS == status)
        status =
            osalHashSHA512Full(dataToHash, k.pData, (DATA_LEN * 2) + HASH_LEN);

    /* Reduce k % field order */
    if (CPA_STATUS_SUCCESS == status)
        status = reduceScalar(&k);

    /* Check the group equation [8][S]B = [8]R + [8][k]A'.  It's
     * sufficient, but not required, to instead check [S]B = R + [k]A'. */

    /* Compute verification point 1, V1  = [S]B */
    if (CPA_STATUS_SUCCESS == status)
        status = pointMuliplication(Bx, By, S, V1x, V1y);

    /* Compute verification point 2, V2 = R + [k]A */

    /* Compute the point [k]A */
    if (CPA_STATUS_SUCCESS == status)
        status = pointMuliplication(Ax, Ay, k.pData, Ax, Ay);

    /* Perform point addition V2 = R + [k]A */
    if (CPA_STATUS_SUCCESS == status)
        status = addPoints(Rx, Ry, Ax, Ay, V2x, V2y);

    /* Check if V1 = V2, [S]B = R + [k]A */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (memcmp(V1x, V2x, DATA_LEN) || memcmp(V1y, V2y, DATA_LEN))
        {
            status = CPA_STATUS_FAIL;
            PRINT_ERR("Verification points do not match\n");
        }
    }

    /* Free memory */
    OS_FREE(dataToHash);
    OS_FREE(k.pData);

    return status;
}

/*****************************************************************************
 * @description
 *     This function performs sign and verify operation using HashEdDSA on
 *     Edwards 25519 curve.
 *
 * @retval CPA_STATUS_SUCCESS       Sign and verify completed successfully.
 * @retval CPA_STATUS_FAIL          Sign and verify failed.
 *
 *****************************************************************************/
CpaStatus ecMontEdwdsDsaPerform(void)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa8U messageHash[HASH_LEN] = {0};   /* Buffer for hash from message */
    Cpa8U publicKey[DATA_LEN] = {0};     /* Buffer for generated public key */
    Cpa8U signature[DATA_LEN * 2] = {0}; /* Buffer for generated signature */

    /* Random generated private key - RFC832 Edwards 25519 TEST SHA(abc) */
    Cpa8U privateKey[DATA_LEN] = {
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77,
        0x58, 0x75, 0x20, 0x91, 0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19,
        0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42};

    char *message = "abc"; /* Message to sign - RFC832 Edwards 25519 TEST
                            * SHA(abc) */

    /* Hash message */
    status = osalHashSHA512Full((Cpa8U *)message, messageHash, strlen(message));
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("Hash message failed\n");

    /* Generate public key */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = edDsaGenPubKey(privateKey, publicKey);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Public key generation failed\n");
        else
            PRINT_DBG("Public Key generated successfully\n");
    }

    /* Sign message */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = edDsaSign(privateKey, messageHash, signature);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Signature generation failed\n");
        else
            PRINT_DBG("Signature generated successfully\n");
    }

    /* Verify sign */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = edDsaVerify(publicKey, messageHash, signature);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Signature verification failed\n");
        else
            PRINT_DBG("Signature verified successfully\n");
    }

    return status;
}

/*****************************************************************************
 * @description
 *     This function gets instance handle and starts cryptographic
 *     component used in sign and verify functions.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus ecMontEdwdsDsaSample(void)
{
    CpaStatus status = CPA_STATUS_FAIL;

    /* Get instance handle */
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
        return CPA_STATUS_FAIL;

    /* Start Cryptographic component */
    status = cpaCyStartInstance(cyInstHandle);

    /* Set address translation */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error set address translation\n");
            return status;
        }
    }

    /* Start polling thread */
    sampleCyStartPolling(cyInstHandle);

    /* Perform sign and verify */
    status = ecMontEdwdsDsaPerform();

    /* Stop the polling thread */
    sampleCyStopPolling();

    /* Stop Cryptographic component */
    cpaCyStopInstance(cyInstHandle);

    return status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
