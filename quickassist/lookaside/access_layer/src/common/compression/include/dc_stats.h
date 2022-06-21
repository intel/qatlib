/****************************************************************************
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
