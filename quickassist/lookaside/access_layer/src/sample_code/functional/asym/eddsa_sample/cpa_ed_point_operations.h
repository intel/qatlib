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
 * @file cpa_ed_point_operations.h
 *
 * @description
 *     This file contains declarations of functions used in Edwards 25519 curve
 *     point operations.
 *
 *****************************************************************************/
#ifndef CPA_ED_POINT_OPERATIONS_H
#define CPA_ED_POINT_OPERATIONS_H

#include "cpa_eddsa_sample.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

/*****************************************************************************
 * @description
 *     This function takes X and Y coordinate and encodes point in a curve to
 *     a single value.
 *
 * @param[in]   pPointX   Pointer to buffer with X coordinate of point on curve
 * @param[in]   pPointY   Pointer to buffer with Y coordinate of point on curve
 *
 * @param[out]  encPoint  Pointer to buffer with encoded point on a curve
 *
 *****************************************************************************/
void encodePoint(Cpa8U *pPointX, Cpa8U *pPointY, Cpa8U *encPoint);

/*****************************************************************************
 * @description
 *     This function takes encoded point value and retrieves X and Y
 *     coordinate of point on a curve.
 *
 * @param[in]   encPoint  Pointer to buffer with encoded point on a curve
 *
 * @param[out]  pPointX   Pointer to buffer with X coordinate of point on curve
 * @param[out]  pPointY   Pointer to buffer with Y coordinate of point on curve
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus decodePoint(Cpa8U *encPoint, Cpa8U *pPointX, Cpa8U *pPointY);

/*****************************************************************************
 * @description
 *     This function takes two points A and B representend as Ax, Ay, Bx, By,
 *     coordinate values and performs point addition on Edwards 25519 curve.
 *     Result is point C represented in Cx and Cy coordinate values. Addition
 *     is performed on extended homogeneous coordinates (X, Y, Z, T),
 *     with x = X/Z, y = Y/Z, x * y = T/Z. Function work for any pair of valid
 *     input points.
 *
 * @param[in]   pPointAx  Pointer to buffer with X coordinate of point A
 * @param[in]   pPointAy  Pointer to buffer with Y coordinate of point A
 * @param[in]   pPointBx  Pointer to buffer with X coordinate of point B
 * @param[in]   pPointBy  Pointer to buffer with X coordinate of point B
 *
 * @param[out]  pPointCx  Pointer to buffer with X coordinate of point C
 * @param[out]  pPointCy  Pointer to buffer with Y coordinate of point C
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus addPoints(Cpa8U *pPointAx,
                    Cpa8U *pPointAy,
                    Cpa8U *pPointBx,
                    Cpa8U *pPointBy,
                    Cpa8U *pPointCx,
                    Cpa8U *pPointCy);

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
#endif
