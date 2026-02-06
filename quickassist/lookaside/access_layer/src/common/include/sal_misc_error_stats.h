/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 ***************************************************************************
 * @file sal_misc_error_stats.h
 *
 * @ingroup SalMiscErrStats
 *
 * The file contains functions handles miscellaneous error global counter
 *
 ***************************************************************************/

#ifndef SAL_MISC_ERR_STATS_H
#define SAL_MISC_ERR_STATS_H

#define SAL_MISC_ERR_STATS_INC(err, service)                                   \
    do                                                                         \
    {                                                                          \
        if (ERR_CODE_MISC_ERROR == (Cpa8S)err && service)                      \
        {                                                                      \
            Sal_IncMiscErrStats(service);                                      \
        }                                                                      \
    } while (0)

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to increase misc error statistics.
 *
 * @param[in] pService         pointer to service instance.
 *
 * @assumptions
 *      Called when misc error reported by firmware.
 * @sideEffects
 *      None
 * @reentrant
 *      None
 * @threadSafe
 *      Yes
 *
 ******************************************************************/

CpaStatus Sal_IncMiscErrStats(sal_service_t *pService);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to get the misc error statistics.
 *
 * @param[in] pService         pointer to service instance.
 * @param[out] pMiscStats      pointer to get misc counter.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 ******************************************************************/
CpaStatus Sal_GetMiscErrStats(sal_service_t *pService, OsalAtomic *pMiscStats);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to initialise misc error statistics and
 *    create misc error stats file.
 *
 * @param[in] pStats         pointer to statistics instance.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      None
 * @threadSafe
 *      None
 *
 ******************************************************************/
CpaStatus Sal_InitMiscErrStats(sal_statistics_collection_t *pStats);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to clear misc error statistics and
 *    remove the misc error stats file.
 *
 * @param[in] pService         pointer to service instance.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 ******************************************************************/
CpaStatus Sal_CleanMiscErrStats(sal_service_t *pService);

#endif
