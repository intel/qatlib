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
 * @file lac_ec_nist_curves.h
 *
 * @ingroup Lac_Ec
 *
 * Definitions for the following NIST recommended elliptic curves:
 *  - PRIME 256 (P256)
 *  - PRIME 384 (P384)
 *  - PRIME 521 (P521)
 *  - KOBLITZ 163 (K163)
 *  - BINARY 163 (B163)
 *  - KOBLITZ 233 (K233)
 *  - BINARY 233 (B233)
 *  - KOBLITZ 571 (K571)
 *  - BINARY 571 (B571)
 *
 *****************************************************************************/

#ifndef LAC_EC_NIST_CURVES_H
#define LAC_EC_NIST_CURVES_H

#include "cpa_types.h" // for Cpa8U

/*********** NIST PRIME 256 CURVE ****************/
#define NIST_GFP_P_256_BIT_POS 256
#define NIST_GFP_A_256_BIT_POS 256
#define NIST_GFP_B_256_BIT_POS 255
#define NIST_GFP_R_256_BIT_POS 256
#define NIST_GFP_GX_256_BIT_POS 255
#define NIST_GFP_GY_256_BIT_POS 255

extern Cpa8U nist_p256_p[];
extern Cpa8U nist_p256_a[];
extern Cpa8U nist_p256_b[];
extern Cpa8U nist_p256_n[];
extern Cpa8U nist_p256_h[];
extern Cpa8U nist_p256_gX[];
extern Cpa8U nist_p256_gY[];

/*********** NIST PRIME 384 CURVE ****************/
#define NIST_GFP_P_384_BIT_POS 384
#define NIST_GFP_A_384_BIT_POS 384
#define NIST_GFP_B_384_BIT_POS 384
#define NIST_GFP_R_384_BIT_POS 384
#define NIST_GFP_GX_384_BIT_POS 384
#define NIST_GFP_GY_384_BIT_POS 382

extern Cpa8U nist_p384_p[];
extern Cpa8U nist_p384_a[];
extern Cpa8U nist_p384_b[];
extern Cpa8U nist_p384_n[];
extern Cpa8U nist_p384_h[];
extern Cpa8U nist_p384_gX[];
extern Cpa8U nist_p384_gY[];

/*********** NIST PRIME 521 CURVE ****************/
#define NIST_GFP_Q_521_BIT_POS 520
#define NIST_GFP_A_521_BIT_POS 520
#define NIST_GFP_B_521_BIT_POS 518
#define NIST_GFP_H_521_BIT_POS 0
#define NIST_GFP_R_521_BIT_POS 520

extern Cpa8U nist_p521_q[];
extern Cpa8U nist_p521_a[];
extern Cpa8U nist_p521_b[];
extern Cpa8U nist_p521_r[];

/*********** NIST 163 KOBLITZ  AND BINARY CURVES ****************/
#define NIST_GF2_Q_163_BIT_POS 163
#define NIST_GF2_A_163_BIT_POS 0
#define NIST_GF2_H_163_BIT_POS 1
#define NIST_GF2_R_163_BIT_POS 162

extern const Cpa8U nist_gf2_163_q[];
extern const Cpa8U nist_gf2_163_a[];
extern const Cpa8U nist_gf2_163_h[];

/*********** NIST 163 KOBLITZ CURVE ****************/

#define NIST_GF2_B_K163_BIT_POS 0

extern const Cpa8U nist_koblitz_gf2_163_b[];
extern const Cpa8U nist_koblitz_gf2_163_r[];

/*********** NIST 163 BINARY CURVE ****************/

#define NIST_GF2_B_B163_BIT_POS 161

extern const Cpa8U nist_binary_gf2_163_b[];
extern const Cpa8U nist_binary_gf2_163_r[];

/*********** NIST 233 KOBLITZ AND BINARY CURVES ****************/
#define NIST_GF2_Q_233_BIT_POS 233
#define NIST_GF2_A_233_BIT_POS 0

extern const Cpa8U nist_gf2_233_q[];

/*********** NIST 233 KOBLITZ CURVE ****************/

#define NIST_GF2_H_K233_BIT_POS 2
#define NIST_GF2_B_K233_BIT_POS 0
#define NIST_GF2_R_K233_BIT_POS 231

extern const Cpa8U nist_koblitz_gf2_233_h[];
extern const Cpa8U nist_koblitz_gf2_233_a[];
extern const Cpa8U nist_koblitz_gf2_233_b[];
extern const Cpa8U nist_koblitz_gf2_233_r[];

/*********** NIST 233 BINARY CURVE ****************/

#define NIST_GF2_H_B233_BIT_POS 1
#define NIST_GF2_B_B233_BIT_POS 230
#define NIST_GF2_R_B233_BIT_POS 232

extern const Cpa8U nist_binary_gf2_233_h[];
extern const Cpa8U nist_binary_gf2_233_a[];
extern const Cpa8U nist_binary_gf2_233_b[];
extern const Cpa8U nist_binary_gf2_233_r[];

/*********** NIST 571 KOBLITZ  AND BINARY CURVES ****************/
#define NIST_GF2_Q_571_BIT_POS 571
#define NIST_GF2_A_571_BIT_POS 0

extern const Cpa8U nist_gf2_571_q[];

/*********** NIST 571 KOBLITZ CURVE ****************/

#define NIST_GF2_B_K571_BIT_POS 0
#define NIST_GF2_H_K571_BIT_POS 2
#define NIST_GF2_R_K571_BIT_POS 569

extern const Cpa8U nist_koblitz_gf2_571_h[];
extern const Cpa8U nist_koblitz_gf2_571_r[];

/*********** NIST 571 BINARY CURVE ****************/
#define NIST_GF2_B_B571_BIT_POS 569
#define NIST_GF2_H_B571_BIT_POS 1
#define NIST_GF2_R_B571_BIT_POS 569

extern const Cpa8U nist_binary_gf2_571_b[];
extern const Cpa8U nist_binary_gf2_571_h[];
extern const Cpa8U nist_binary_gf2_571_r[];

#endif /* LAC_EC_NIST_CURVES_H */
