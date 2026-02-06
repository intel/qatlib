/**
 *****************************************************************************
 *
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
