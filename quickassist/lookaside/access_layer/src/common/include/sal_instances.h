/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

#ifndef SAL_INSTANCES_H
#define SAL_INSTANCES_H

CpaStatus Lac_GetCyInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U numInstances,
    CpaInstanceHandle *pInstances);

CpaStatus Lac_GetCyNumInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *pNumInstances);

CpaStatus Lac_GetDcInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U numInstances,
    CpaInstanceHandle *pInstances);

CpaStatus Lac_GetDcNumInstancesByType(
    const CpaAccelerationServiceType accelerationServiceType,
    Cpa16U *pNumInstances);

#endif /* SAL_INSTANCES_H */
