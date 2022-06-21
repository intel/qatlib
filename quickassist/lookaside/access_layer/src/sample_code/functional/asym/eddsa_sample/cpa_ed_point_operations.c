/***************************************************************************
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

/***************************************************************************
 * @file cpa_ed_point_operations.c
 *
 * @description
 *     This file contains functions used in point operations on Edwards 25519
 *     curve.
 *
 ***************************************************************************/

#include "cpa_ed_point_operations.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

extern int gDebugParam;

/* d of edwards25519 in little endian integer */
Cpa8U dFactor[32] = {0xA3, 0x78, 0x59, 0x13, 0xCA, 0x4D, 0xEB, 0x75,
                     0xAB, 0xD8, 0x41, 0x41, 0x4D, 0x0A, 0x70, 0x00,
                     0x98, 0xE8, 0x79, 0x77, 0x79, 0x40, 0xC7, 0x8C,
                     0x73, 0xFE, 0x6F, 0x2B, 0xEE, 0x6C, 0x03, 0x52};

/* p of edwards25519 in little endian integer */
Cpa8U prime[32] = {0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

/*****************************************************************************
 * @description
 *     This function checks if B value is greater than A value
 *
 * @param[in]  A   pointer to flat buffer with little endian integer
 * @param[in]  B   pointer to flat buffer with little endian integer
 *
 * @retval CPA_STATUS_SUCCESS        B value is greater or equals A value
 * @retval CPA_STATUS_FAIL           B value is smaller than A value
 * @retval CPA_STATUS_INVALID_PARAM  B dataLenInBytes is equal 0
 *
 *****************************************************************************/
static CpaStatus checkIfSmaller(CpaFlatBuffer *A, CpaFlatBuffer *B)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32S i = 0;

    if (B->dataLenInBytes == 0)
        return CPA_STATUS_INVALID_PARAM;

    for (i = B->dataLenInBytes - 1; i >= 0; i--)
    {
        if (A->pData[i] > B->pData[i])
            return CPA_STATUS_FAIL;
        else if (A->pData[i] < B->pData[i])
            return CPA_STATUS_SUCCESS;
    }

    return status;
}

/*****************************************************************************
 * @description
 *     This function checks if flat buffer integer value equals zero.
 *
 * @param[in] fb pointer to flat buffer with integer value
 *
 * @retval CPA_STATUS_SUCCESS       Integer value equals zero
 * @retval CPA_STATUS_FAIL          Integer value is greater than zero
 *
 *****************************************************************************/
static CpaStatus checkIfBufferEqZero(CpaFlatBuffer *fb)
{
    Cpa32S i = 0;

    for (i = 0; i < fb->dataLenInBytes; i++)
        if (fb->pData[i] != 0)
            return CPA_STATUS_FAIL;

    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * @description
 *     This function sets flat buffer integer value.
 *
 * @param[in]  fb     Pointer to flat buffer
 * @param[in]  value  Value to set in flat buffer
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus setFlatBufferValue(CpaFlatBuffer *fb, Cpa8U value)
{
    CpaStatus status = CPA_STATUS_FAIL;

    if (fb->pData != NULL)
    {
        OS_FREE(fb->pData);
        fb->pData = NULL;
    }

    status = OS_MALLOC(&fb->pData, sizeof(Cpa8U));
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("Memory alloc error\n");

    if (CPA_STATUS_SUCCESS == status)
    {
        fb->dataLenInBytes = sizeof(Cpa8U);
        fb->pData[0] = value;
    }

    return status;
}

void encodePoint(Cpa8U *pPointX, Cpa8U *pPointY, Cpa8U *encPoint)
{
    /* Copy Y value */
    memcpy(encPoint, pPointY, DATA_LEN);

    /* Set LSB from X to MSB Y */
    if (CHK_BIT(pPointX[0], 0))
        SET_BIT(encPoint[DATA_LEN - 1], 7);
    else
        CLR_BIT(encPoint[DATA_LEN - 1], 7);
}

CpaStatus decodePoint(Cpa8U *encPoint, Cpa8U *pPointX, Cpa8U *pPointY)
{
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa8U x_0 = 0;         /* Least significant bit of X coordinate */
    CpaFlatBuffer d = {0}; /* d value of Edwards 25519 curve */
    CpaFlatBuffer p = {0}; /* p value of Edwards 25519 curve */
    CpaFlatBuffer X = {0}; /* Decoded X coordinate */
    CpaFlatBuffer Y = {0}; /* Decoded Y coordinate */
    CpaFlatBuffer U = {0}; /* U factor */
    CpaFlatBuffer V = {0}; /* V factor */
    CpaFlatBuffer A = {0}; /* Temp value */
    CpaFlatBuffer B = {0}; /* Temp value */
    CpaFlatBuffer C = {0}; /* Temp value */
    CpaFlatBuffer D = {0}; /* Temp value */
    CpaFlatBuffer E = {0}; /* Temp value */

    /* Init values d, p, Y */
    status = copyToFlatBuffer(&d, dFactor, DATA_LEN);
    status |= copyToFlatBuffer(&p, prime, DATA_LEN);
    status |= copyToFlatBuffer(&Y, encPoint, DATA_LEN);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Least significant bit of the x-coordinate x_0 */
        if (CHK_BIT(encPoint[DATA_LEN - 1], 7))
            SET_BIT(x_0, 0);
        else
            CLR_BIT(x_0, 0);

        /* Clear most significant bit of Y coordinate */
        CLR_BIT(Y.pData[DATA_LEN - 1], 7);

        /* If Y >= p decode fails */
        status = checkIfSmaller(&Y, &p);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Y is >= p - Point decode fail\n");
    }

    /* To recover the x-coordinate, the curve equation implies
     * (x^2) % p = ((y^2 - 1) / (d * y^2 + 1)) % p. Let u = y^2 - 1 and
     * v = d * y^2 + 1. To compute the square root of (u/v), the first step is
     * to compute the candidate root x = (u/v)^((p+3)/8). This can be done with
     * using a single modular powering for both the inversion of v and the
     * square root: x = ((u * (v^3)) * ((u * (v^7))^((p - 5) / 8))) % p
     */

    /* U = (y^2 - 1) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModSqr(&A, &Y, &p);      /* A = (A^2) % p */
        status |= setFlatBufferValue(&E, 1);    /* E = 1 */
        status |= bigNumModSub(&U, &A, &E, &p); /* U = (A - E) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* V = (d * y^2 + 1) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModMul(&A, &d, &A, &p);  /* A = (d * A) % p */
        status |= bigNumModAdd(&V, &A, &E, &p); /* V = (A + E) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* A = (u * v^3) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = setFlatBufferValue(&E, 3);     /* E = 3 */
        status |= bigNumModExp(&A, &V, &E, &p); /* A = (V^E) % p*/
        status |= bigNumModMul(&A, &U, &A, &p); /* A = (U * A) % p*/
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* B = (u * v^7) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = setFlatBufferValue(&E, 7);     /* E = 7 */
        status |= bigNumModExp(&B, &V, &E, &p); /* B = (V^E) % p */
        status |= bigNumModMul(&B, &U, &B, &p); /* B = (U * B) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* C = ((p-5) / 8) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = setFlatBufferValue(&E, 5);     /* E = 5 */
        status |= bigNumModSub(&C, &p, &E, &p); /* C = (p - E) % p */
        status |= setFlatBufferValue(&E, 8);    /* E = 8 */
        status |= bigNumModInv(&D, &E, &p);     /* D = (1/E) % p */
        status |= bigNumModMul(&C, &C, &D, &p); /* C = (C * D) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* X = (A * B^C) % p */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModExp(&D, &B, &C, &p);  /* D = (B^C) % p */
        status |= bigNumModMul(&X, &A, &D, &p); /* X = (A * D) %p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    /* If v * x^2 = u, x is a square root */

    /* B = (v * x^2) % p; */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModSqr(&A, &X, &p);      /* A = (X^2) % p */
        status |= bigNumModMul(&B, &V, &A, &p); /* B = (V * A) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point decode failed\n");
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Check if v * x^2 = u  */
        if (memcmp(B.pData, U.pData, U.dataLenInBytes))
        {
            /* Check if If v * x^2 = -u is a square root */
            status = setFlatBufferValue(&E, 0);     /* E = 0 */
            status |= bigNumModSub(&U, &E, &U, &p); /* U = (E - U) % p */
            if (CPA_STATUS_SUCCESS != status)
                PRINT_ERR("Point decode failed\n");

            if (CPA_STATUS_SUCCESS == status &&
                (memcmp(B.pData, U.pData, U.dataLenInBytes) == 0))
            {
                /* set x <-- (x * 2^((p-1) /4)) % p, which is a square root*/
                status = setFlatBufferValue(&E, 4);     /* E = 4 */
                status |= bigNumModInv(&C, &E, &p);     /* C = (1/E) % p */
                status |= setFlatBufferValue(&E, 1);    /* E = 1 */
                status |= bigNumModSub(&A, &p, &E, &p); /* A = (p - 1) % p */
                status |= bigNumModMul(&A, &A, &C, &p); /* A = (A * C) % p */
                status |= setFlatBufferValue(&E, 2);    /* E = 2 */
                status |= bigNumModExp(&D, &E, &A, &p); /* D = (2^A) % p */
                status |= bigNumModMul(&X, &X, &D, &p); /* X = (X * D) % p */
                if (CPA_STATUS_SUCCESS != status)
                    PRINT_ERR("Point decode failed\n");
            }
            else
            {
                PRINT_ERR("No square root - Point decode fail\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    /* If x = 0 and x_0 = 1, decoding fails */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (CPA_STATUS_SUCCESS == checkIfBufferEqZero(&X) && x_0 == 1)
        {
            PRINT_ERR("Point decode fail\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /* If x_0 != x % 2, set x <-- p - x */
    if (CPA_STATUS_SUCCESS == status)
    {
        if ((CHK_BIT(X.pData[0], 0)) != x_0)
        {
            status = bigNumModSub(&X, &p, &X, &p); /* X =  (p - X) % p */
            if (CPA_STATUS_SUCCESS != status)
                PRINT_ERR("Point decode failed\n");
        }
    }

    /* Copy x and y to output buffers */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pPointX, X.pData, X.dataLenInBytes);
        memcpy(pPointY, Y.pData, Y.dataLenInBytes);
    }

    /* Free memory */
    OS_FREE(d.pData);
    OS_FREE(p.pData);
    OS_FREE(X.pData);
    OS_FREE(Y.pData);
    OS_FREE(U.pData);
    OS_FREE(V.pData);
    OS_FREE(A.pData);
    OS_FREE(B.pData);
    OS_FREE(C.pData);
    OS_FREE(D.pData);
    OS_FREE(E.pData);

    return status;
}

CpaStatus addPoints(Cpa8U *pPointAx,
                    Cpa8U *pPointAy,
                    Cpa8U *pPointBx,
                    Cpa8U *pPointBy,
                    Cpa8U *pPointCx,
                    Cpa8U *pPointCy)
{
    CpaStatus status = CPA_STATUS_FAIL;
    /* Field values buffers */
    CpaFlatBuffer d = {0}, p = {0};
    /* Input/ Ouptut values buffers */
    CpaFlatBuffer Ax = {0}, Ay = {0}, Bx = {0}, By = {0}, Cx = {0}, Cy = {0};
    /* Extended point values buffers */
    CpaFlatBuffer X1 = {0}, Y1 = {0}, Z1 = {0}, T1 = {0};
    CpaFlatBuffer X2 = {0}, Y2 = {0}, Z2 = {0}, T2 = {0};
    CpaFlatBuffer X3 = {0}, Y3 = {0}, Z3 = {0}, T3 = {0};
    /* Point addition temporary buffers */
    CpaFlatBuffer A = {0}, B = {0}, C = {0}, D = {0}, E = {0}, F = {0}, G = {0},
                  H = {0}, I = {0}, J = {0};

    /* Init field values */
    status = copyToFlatBuffer(&d, dFactor, DATA_LEN);
    status |= copyToFlatBuffer(&p, prime, DATA_LEN);
    if (CPA_STATUS_SUCCESS != status)
        PRINT_ERR("Point addition failed\n");

    /* Init input points values */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = copyToFlatBuffer(&Ax, pPointAx, DATA_LEN);
        status |= copyToFlatBuffer(&Ay, pPointAy, DATA_LEN);
        status |= copyToFlatBuffer(&Bx, pPointBx, DATA_LEN);
        status |= copyToFlatBuffer(&By, pPointBy, DATA_LEN);
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point addition failed\n");
    }

    /* For point addition, a point (x,y) is represented in extended homogeneous
     * coordinates (X, Y, T, Z) and an extended affine point (x, y, xy) which is
     * equally written as (x, y, xy, 1). */

    /* Set extended points values */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = copyToFlatBuffer(&X1, pPointAx, DATA_LEN);  /* X1 = Ax */
        status |= copyToFlatBuffer(&Y1, pPointAy, DATA_LEN); /* Y1 = Ay */
        status |= bigNumModMul(&T1, &Ax, &Ay, &p); /* T1 = (Ax * Ay) % p */
        status |= setFlatBufferValue(&Z1, 1);      /* Z1 = 1 */

        status |= copyToFlatBuffer(&X2, pPointBx, DATA_LEN); /* X2 = Bx */
        status |= copyToFlatBuffer(&Y2, pPointBy, DATA_LEN); /* Y2 = By */
        status |= bigNumModMul(&T2, &Bx, &By, &p); /* T2 = (Bx * By) % p */
        status |= setFlatBufferValue(&Z2, 1);      /* Z2 = 1  */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point addition failed\n");
    }

    /*  The formula for adding two points, (x3,y3) = (x1,y1)+(x2,y2),
     *  on twisted Edwards curves with a=-1, square a, and non-square d.
     *  It works for any pair of valid input points.
     *
     *  A = (Y1-X1)*(Y2-X2)
     *  B = (Y1+X1)*(Y2+X2)
     *  C = T1*2*d*T2
     *  D = Z1*2*Z2
     *  E = B-A
     *  F = D-C
     *  G = D+C
     *  H = B+A
     *  X3 = E*F
     *  Y3 = G*H
     *  T3 = E*H
     *  Z3 = F*G
     */

    /* Add two extended points */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModSub(&I, &Y1, &X1, &p);  /* I = (Y1 - X1) % p */
        status |= bigNumModSub(&J, &Y2, &X2, &p); /* J = (Y2 - X2) % p */
        status |= bigNumModMul(&A, &I, &J, &p);   /* A = (I * J) % p */
        status |= bigNumModAdd(&I, &Y1, &X1, &p); /* I = (Y1 + X1) % p */
        status |= bigNumModAdd(&J, &Y2, &X2, &p); /* J = (Y2 + X2) % p */
        status |= bigNumModMul(&B, &I, &J, &p);   /* B = (I * J) % p*/
        status |= setFlatBufferValue(&I, 2);      /* I = 2 */
        status |= bigNumModMul(&J, &T1, &I, &p);  /* J = (T1 * 2) % p; */
        status |= bigNumModMul(&J, &J, &d, &p);   /* J = (J * d) % p */
        status |= bigNumModMul(&C, &J, &T2, &p);  /* C = (J * T2) % p */
        status |= bigNumModMul(&D, &Z1, &I, &p);  /* D = (Z1 * 2) % p */
        status |= bigNumModMul(&D, &D, &Z2, &p);  /* D = (D * Z2) % p */
        status |= bigNumModSub(&E, &B, &A, &p);   /* E = (B - A) % p */
        status |= bigNumModSub(&F, &D, &C, &p);   /* F = (D - C) % p */
        status |= bigNumModAdd(&G, &D, &C, &p);   /* G = (D + C) % p */
        status |= bigNumModAdd(&H, &B, &A, &p);   /* H = (B + A) % p */
        status |= bigNumModMul(&X3, &E, &F, &p);  /* X3 = (E * F) % p */
        status |= bigNumModMul(&Y3, &G, &H, &p);  /* Y3 = (G * H) % p */
        status |= bigNumModMul(&T3, &E, &H, &p);  /* T3 = (E * H) % p*/
        status |= bigNumModMul(&Z3, &F, &G, &p);  /* Z3 = (F * G) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point addition failed\n");
    }

    /* Decode points from extended notation x = X/Z, y = Y/Z */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = bigNumModInv(&Z3, &Z3, &p);       /* Z3 = (1/Z3) % p */
        status |= bigNumModMul(&Cx, &X3, &Z3, &p); /* Cx = (X3 * Z3) % p */
        status |= bigNumModMul(&Cy, &Y3, &Z3, &p); /* Cy = (Y3 * Z3) % p */
        if (CPA_STATUS_SUCCESS != status)
            PRINT_ERR("Point addition failed\n");
    }

    /* Copy values to output buffers */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pPointCx, Cx.pData, DATA_LEN);
        memcpy(pPointCy, Cy.pData, DATA_LEN);
    }

    /* Free memory */
    OS_FREE(d.pData);
    OS_FREE(p.pData);
    OS_FREE(Ax.pData);
    OS_FREE(Ay.pData);
    OS_FREE(Bx.pData);
    OS_FREE(By.pData);
    OS_FREE(Cx.pData);
    OS_FREE(Cy.pData);
    OS_FREE(X1.pData);
    OS_FREE(Y1.pData);
    OS_FREE(T1.pData);
    OS_FREE(Z1.pData);
    OS_FREE(X2.pData);
    OS_FREE(Y2.pData);
    OS_FREE(T2.pData);
    OS_FREE(Z2.pData);
    OS_FREE(X3.pData);
    OS_FREE(Y3.pData);
    OS_FREE(T3.pData);
    OS_FREE(Z3.pData);
    OS_FREE(A.pData);
    OS_FREE(B.pData);
    OS_FREE(C.pData);
    OS_FREE(D.pData);
    OS_FREE(E.pData);
    OS_FREE(F.pData);
    OS_FREE(G.pData);
    OS_FREE(H.pData);
    OS_FREE(I.pData);
    OS_FREE(J.pData);

    return status;
}
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
