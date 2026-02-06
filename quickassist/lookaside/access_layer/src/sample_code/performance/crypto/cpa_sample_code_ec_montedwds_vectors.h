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
 * @file cpa_sample_code_eced_vectors.h
 *
 * @defgroup ecMontEdwdsThreads
 *
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This file contains structure declaration for test vectors
 *      and getEcedTestVectors function definition used in ECED test
 *
 *****************************************************************************/
#ifndef CPA_SAMPLE_CODE_ECMONTEDWDS_VECTORS_H
#define CPA_SAMPLE_CODE_ECMONTEDWDS_VECTORS_H

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_sample_code_crypto_utils.h"

#if CY_API_VERSION_AT_LEAST(2, 3)
/**
 *****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This structure contains data relating to test vectors used in ECED
 *      test.
 *
 ****************************************************************************/
typedef struct sample_ec_montedwds_vectors_s
{
    /* pointer to x vector */
    Cpa8U *x;
    /* x vector size */
    Cpa32U xSize;
    /* pointer to y vector */
    Cpa8U *y;
    /* y vector size */
    Cpa32U ySize;
    /* pointer to k vector */
    Cpa8U *k;
    /* k vector size */
    Cpa32U kSize;
    /* pointer to u vector - generated x */
    Cpa8U *u;
    /* u vector size */
    Cpa32U uSize;
    /* pointer to v vector - generated y */
    Cpa8U *v;
    /* v vector size */
    Cpa32U vSize;
    /* number of vectors in selected curve type */
    Cpa32U vectorsNum;
} sample_ec_montedwds_vectors_t;

/**
 *****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      This functions selects vectors used in ECED test
 *
 ****************************************************************************/
CpaStatus getEcMontEdwdsTestVectors(CpaBoolean generator,
                                    CpaCyEcMontEdwdsCurveType curveType,
                                    Cpa32U vector,
                                    sample_ec_montedwds_vectors_t *testVectors);

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
#endif
