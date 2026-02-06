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
 *****************************************************************************
 * @file lac_dsa.h
 *
 * @defgroup Lac_Dsa     DSA
 *
 * @ingroup LacAsym
 *
 * Interfaces exposed by the DSA component
 *
 * @lld_start
 *
 * @lld_overview
 * This is the DSA feature implementation.  It implements 7 DSA API services:
 * parameter generation (p, g, y), signature generation (r, s, rs), and
 * signature verification.  Statistics are maintained for each service.  For
 * each service the parameters supplied by the client are checked, and then
 * input/output argument lists are constructed before calling the PKE QAT
 * Comms layer to create and send a request to the QAT.
 *
 * For DSA P Parameter Generation two inputs are required by the QAT which are
 * handled internally so the client is not aware of them.  They are products
 * of small primes, used by the QAT to perform a GCD (or alternatively
 * Pollard-Rho) test on the generated P parameter as an initial (non-robust,
 * but fast) primality test.  These two inputs are allocated and managed
 * internally by this component.
 *
 * For Verification service the output is the result of the verification
 * returned by the QAT in the form of pass/fail status. The status is
 * returned to the caller.
 *
 * In all other cases the service implementations are a straightforward
 * marshalling of client-supplied parameters for the QAT.  I.e. there is
 * minimal logic handled by this component.  Buffer alignment, and padding up
 * to a whole number of quadwords, is handled by the PKE QAT Comms layer.
 *
 * @lld_initialisation
 * On initialization this component allocates the two product-of-small-primes
 * parameters (psp1 and psp2) for the DSA P Parameter Generation operation.
 * It also clears the stats.
 *
 * @note
 * The DSA feature may be called in Asynchronous or Synchronous modes.
 * In Asynchronous mode the user supplies a Callback function to the API.
 * Control returns to the client after the message has been sent to the QAT and
 * the Callback gets invoked when the QAT completes the operation. There is NO
 * BLOCKING. This mode is preferred for maximum performance.
 * In Synchronous mode the client supplies no Callback function pointer (NULL)
 * and the point of execution is placed on a wait-queue internally, and this is
 * de-queued once the QAT completes the operation. Hence, Synchronous mode is
 * BLOCKING. So avoid using in an interrupt context. To achieve maximum
 * performance from the API Asynchronous mode is preferred.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 *****************************************************************************/

/*****************************************************************************/

#ifndef LAC_DSA_H
#define LAC_DSA_H

/*
******************************************************************************
* Include public/global header files
******************************************************************************
*/

#include "cpa.h"

/*
*******************************************************************************
* Include private header files
*******************************************************************************
*/

/*
 ******************************************************************************
 * @ingroup LacDsa
 *      DSA {L,N} pairs supported by FIPS186-3
 *
 * @description
 *      enumeration containing the possible {L,N} pairs input
 *
 *******************************************************************************/
typedef enum lac_dsa_ln_pairs_s
{
    LAC_DSA_INVALID_PAIR = 0,
    LAC_DSA_1024_160_PAIR,
    LAC_DSA_2048_224_PAIR,
    LAC_DSA_2048_256_PAIR,
    LAC_DSA_3072_256_PAIR
} lac_dsa_ln_pairs_t;

/*
 ******************************************************************************
 * @ingroup LacDsa
 *      DSA L values supported by FIPS186-3
 *
 * @description
 *      enumeration containing the possible L values
 *
 *******************************************************************************/
typedef enum lac_dsa_l_values_s
{
    LAC_DSA_L_INVALID = 0,
    LAC_DSA_L_1024,
    LAC_DSA_L_2048,
    LAC_DSA_L_3072
} lac_dsa_l_values_t;

/*
 ******************************************************************************
 * @ingroup LacDsa
 *      DSA N values supported by FIPS186-3
 *
 * @description
 *      enumeration containing the possible N values
 *
 *******************************************************************************/
typedef enum lac_dsa_n_values_s
{
    LAC_DSA_N_INVALID = 0,
    LAC_DSA_N_160,
    LAC_DSA_N_224,
    LAC_DSA_N_256
} lac_dsa_n_values_t;

/**
 *******************************************************************************
 * @ingroup Lac_Dsa
 *      print the DSA stats to standard output
 *
 * @description
 *      For each engine this function copies the stats using the function
 *      cpaCyDsaQueryStats64. It then prints contents of this structure to
 *      standard output
 *
 * @see cpaCyDsaQueryStats64()
 *
 *****************************************************************************/
void LacDsa_StatsShow(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup Lac_Dsa
 *      Compile time check of FW interface
 *
 * @description
 *      Performs a compile time check of PKE interface to ensure IA assumptions
 *      about the interface are valid.
 *
 *****************************************************************************/
void LacDsa_CompileTimeAssertions(void);

#endif /* LAC_DSA_H */
