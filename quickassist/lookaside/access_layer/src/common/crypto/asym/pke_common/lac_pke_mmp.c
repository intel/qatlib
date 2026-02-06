/******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 *****************************************************************************/

/**
 ***************************************************************************
 * @file lac_pke_mmp.c
 *
 * @ingroup LacAsymCommonMmp
 *
 * Implementation of mmp related functions
 ******************************************************************************/

/*
********************************************************************************
* Include public/global header files
********************************************************************************
*/
#include "cpa.h"
#include "lac_common.h"

#include "lac_pke_mmp.h"

/*
********************************************************************************
* Include private header files
********************************************************************************
*/

/*
********************************************************************************
* Static Variables
********************************************************************************
*/

/*
********************************************************************************
* Define static function definitions
********************************************************************************
*/

/*
********************************************************************************
* Global Variables
********************************************************************************
*/

/*
********************************************************************************
* Define public/global function definitions
********************************************************************************
*/

Cpa32U LacPke_GetMmpId(Cpa32U sizeInBits,
                       const Cpa32U pSizeIdTable[][LAC_PKE_NUM_COLUMNS],
                       Cpa32U numTableEntries)
{
    Cpa32U id = LAC_PKE_INVALID_FUNC_ID;
    Cpa32U sizeIndex = 0;

    for (sizeIndex = 0; sizeIndex < numTableEntries; sizeIndex++)
    {
        if (pSizeIdTable[sizeIndex][LAC_PKE_SIZE_COLUMN] == sizeInBits)
        {
            id = pSizeIdTable[sizeIndex][LAC_PKE_ID_COLUMN];
            break;
        }
    }

    return id;
}

Cpa32U LacPke_GetIndex_VariableSize(
    Cpa32U sizeInBits,
    const Cpa32U pSizeIdTable[][LAC_PKE_NUM_COLUMNS],
    Cpa32U numTableEntries)
{
    Cpa32U index = LAC_PKE_INVALID_INDEX;
    Cpa32U sizeIndex = 0;

    for (sizeIndex = 0;
         (sizeIndex < numTableEntries) && (LAC_PKE_INVALID_INDEX == index);
         sizeIndex++)
    {
        if (sizeInBits <= pSizeIdTable[sizeIndex][LAC_PKE_SIZE_COLUMN])
        {
            index = sizeIndex;
            break;
        }
    }

    return index;
}
