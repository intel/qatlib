/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *******************************************************************************
 * @file lac_rsa_stats_p.h
 *
 * @ingroup LacRsa
 *
 * @description
 *      This file contains the definitions and prototypes for RSA
 *      statistics.
 *
 * @lld_start
 *      In the LAC API the stats fields are defined as Cpa32U but
 *      OsalAtomic is the type that the atomic API supports. Therefore we
 *      need to define a structure internally with the same fields as the API
 *      stats structure, but each field must be of type OsalAtomic.
 *
 *      - <b>Incrementing Statistics:</b>\n
 *      Atomically increment the statistic on the internal stats structure.
 *
 *      - <b>Providing a copy of the stats back to the user:</b>\n
 *      Use atomicGet to read the atomic variable for each stat field in the
 *      local internal stat structure. These values are saved in structure
 *      (as defined by the LAC API) that the client will provide a pointer
 *      to as a parameter.
 *
 *      - <b>Stats Show:</b>\n
 *      Use atomicGet to read the atomic variables for each field in the local
 *      internal stat structure and print to the screen
 *
 *      - <b>Stats Array:</b>\n
 *      A macro is used to get the offset off the stat in the structure. This
 *      offset is passed to a function which uses it to increment the stat
 *      at that offset.
 *
 * @lld_end
 *
 ***************************************************************************/

/******************************************************************************/

#ifndef _LAC_RSA_STATS_P_H_
#define _LAC_RSA_STATS_P_H_

/**
*******************************************************************************
* @ingroup LacRsa
*      increment an RSA statistic
*
* @description
*      Increment the statistics
*
* @param[in] statistic         The field in the statistics structure to be
*                              incremented
* @param[in] instanceHandle    instanceHandle
*
* @retval None
*
*****************************************************************************/
#ifndef DISABLE_STATS
#define LAC_RSA_STAT_INC(statistic, instanceHandle)                            \
    LacRsa_StatsInc(offsetof(CpaCyRsaStats64, statistic), instanceHandle)
#else
/* Stats disabled */
#define LAC_RSA_STAT_INC(statistic, instanceHandle)
#endif

/**
 *******************************************************************************
 * @ingroup LacRsa
 *      This function allocates and clears the Rsa statistics for
 *      the given accel handle
 * @param[in] instanceHandle    instanceHandle
 * @retval CPA_STATUS_SUCCESS   initialization successful
 * @retval CPA_STATUS_RESOURCE  allocation of stats array failed
 ******************************************************************************/
CpaStatus LacRsa_StatsInit(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacRsa
 *      This function increments the given Rsa stat
 *
 * @param[in] offset            offset of stat field in structure
 * @param[in] instanceHandle    the instanceHandle whose statistics we are
 *                              dealing with
 * @retval None
 ******************************************************************************/
#ifndef DISABLE_STATS
void LacRsa_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle);
#endif

/**
 *******************************************************************************
 * @ingroup LacRsa
 *      This function prints the stats to standard out.
 * @param[in] instanceHandle    instanceHandle
 * @retval None
 ******************************************************************************/
void LacRsa_StatsShow(CpaInstanceHandle instanceHandle);

#endif /* _LAC_RSA_STATS_H_ */
