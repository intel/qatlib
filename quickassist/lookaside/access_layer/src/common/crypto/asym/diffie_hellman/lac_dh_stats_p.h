/*
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 */

/**
 *******************************************************************************
 * @file lac_dh_stats_p.h  Definitions and prototypes for Diffie Hellman stats
 *
 * @ingroup LacDh
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

#ifndef _LAC_DH_STATS_P_H_
#define _LAC_DH_STATS_P_H_

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/

#include "cpa.h"
#include "cpa_cy_dh.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/******************************************************************************/

/**
*******************************************************************************
* Increment a diffie hellman statistic
*
* @description
*      Increment the statistics
*
* @param[in] statistic         The field in the statistics structure to be
*                              incremented
* @param[in] instanceHandle    accel handle
*
* @retval None
*
*****************************************************************************/
#ifndef DISABLE_STATS
#define LAC_DH_STAT_INC(statistic, instanceHandle)                             \
    LacDh_StatsInc(offsetof(CpaCyDhStats64, statistic), instanceHandle)
#else
/* Stats disabled */
#define LAC_DH_STAT_INC(statistic, instanceHandle)
#endif

/**
 *******************************************************************************
 * @ingroup LacDh
 *      Init Statistics structures
 *
 * @description
 *      This function allocates stats arrays and clears the DH statistics
 *      for the given instance handle.
 *
 * @param[in] instanceHandle        Instance Handle
 *
 * @retval CPA_STATUS_SUCCESS   initialization successful
 * @retval CPA_STATUS_RESOURCE  array allocation failed
 ******************************************************************************/
CpaStatus LacDh_StatsInit(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 *      This function increments the given DH stat
 *
 * @param[in] offset            offset of stat field in structure
 * @param[in] instanceHandle    the acceleration handle whose statistics we are
 *                              dealing with
 * @retval None
 ******************************************************************************/
#ifndef DISABLE_STATS
void LacDh_StatsInc(Cpa32U offset, CpaInstanceHandle instanceHandle);
#endif

/**
 *******************************************************************************
 * @ingroup LacDh
 *      This function prints the stats to standard out.
 * @retval None
 ******************************************************************************/
void LacDh_StatsShow(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup LacDh
 *      Compile time check of FW interface
 *
 * @description
 *      Performs a compile time check of PKE interface to ensure IA assumptions
 *      about the interface are valid.
 *
 *****************************************************************************/
void LacDh_CompileTimeAssertions(void);

#endif /* _LAC_DH_STATS_H_ */
