/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/**
 *****************************************************************************
 * @file dc_stats.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression stats parameters.
 *
 *****************************************************************************/
#ifndef DC_STATS_H_
#define DC_STATS_H_

/* Number of Compression statistics */
#define COMPRESSION_NUM_STATS (sizeof(CpaDcStats) / sizeof(Cpa64U))

#ifndef DISABLE_STATS
/* Macro to increment a Compression stat (derives offset into array of
 * atomics) */
#define COMPRESSION_STAT_INC(statistic, pService)                              \
    do                                                                         \
    {                                                                          \
        if (CPA_TRUE == pService->generic_service_info.stats->bDcStatsEnabled) \
        {                                                                      \
            osalAtomicInc(                                                     \
                &pService->pCompStatsArr[offsetof(CpaDcStats, statistic) /     \
                                         sizeof(Cpa64U)]);                     \
        }                                                                      \
    } while (0)
#else
#define COMPRESSION_STAT_INC(statistic, pService)
#endif

/* Macro to get all Compression stats (from internal array of atomics) */
#define COMPRESSION_STATS_GET(compStats, pService)                             \
    do                                                                         \
    {                                                                          \
        int i;                                                                 \
        for (i = 0; i < COMPRESSION_NUM_STATS; i++)                            \
        {                                                                      \
            ((Cpa64U *)compStats)[i] =                                         \
                osalAtomicGet(&pService->pCompStatsArr[i]);                    \
        }                                                                      \
    } while (0)

/* Macro to reset all Compression stats */
#define COMPRESSION_STATS_RESET(pService)                                      \
    do                                                                         \
    {                                                                          \
        int i;                                                                 \
        for (i = 0; i < COMPRESSION_NUM_STATS; i++)                            \
        {                                                                      \
            osalAtomicSet(0, &pService->pCompStatsArr[i]);                     \
        }                                                                      \
    } while (0)

/**
*******************************************************************************
* @ingroup Dc_DataCompression
*      Initialises the compression stats
*
* @description
*      This function allocates and initialises the stats array to 0
*
* @param[in] pService          Pointer to a compression service structure
*
* @retval CPA_STATUS_SUCCESS   initialisation successful
* @retval CPA_STATUS_RESOURCE  array allocation failed
*
*****************************************************************************/
CpaStatus dcStatsInit(sal_compression_service_t *pService);

/**
*******************************************************************************
* @ingroup Dc_DataCompression
*      Frees the compression stats
*
* @description
*      This function frees the stats array
*
* @param[in] pService          Pointer to a compression service structure
*
* @retval None
*
*****************************************************************************/
void dcStatsFree(sal_compression_service_t *pService);

/**
*******************************************************************************
* @ingroup Dc_DataCompression
*      Resets the compression stats
*
* @description
*      This function resets the stats array
*
* @param[in] pService          Pointer to a compression service structure
*
* @retval None
*
*****************************************************************************/
void dcStatsReset(sal_compression_service_t *pService);

#endif /* DC_STATS_H_ */
