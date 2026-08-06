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
 ******************************************************************************
 * @file  kpt_rsa_sample_op.c
 *
 *****************************************************************************/

#include "kpt_sample_common.h"

#define KEY_SIZE_3072_BIT 3072
#define BITS_IN_BYTE 8
#define KEY_PAIRS_NUM 2
#define MSB_SETTING (0x80)

/* AAD value is hardcode in KPT rather than random number, see KPT document */
static const Cpa8U aad[] = { 0x06, 0x08, 0x2A, 0x86, 0x48,
                             0x86, 0xF7, 0x0D, 0x01, 0x01 };

static const Cpa8U iv[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc };

static const Cpa8U sampleSWK[] = {
    0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56,
    0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34,
    0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
};

static const Cpa8U qinv_3072[] = {
    0x88, 0x12, 0x11, 0x81, 0x47, 0x68, 0x02, 0x4A, 0xCA, 0x57, 0x28, 0x3E,
    0x2D, 0x33, 0xA3, 0x10, 0x11, 0x77, 0x7F, 0x32, 0x14, 0x08, 0x29, 0xBF,
    0xED, 0x2F, 0x5E, 0x1B, 0x76, 0x63, 0x95, 0x11, 0x61, 0x2F, 0xB2, 0x85,
    0x17, 0xE7, 0x66, 0x71, 0x3D, 0xB4, 0xA6, 0x35, 0x3E, 0x04, 0x1E, 0x23,
    0xE3, 0xF3, 0xF8, 0x87, 0x23, 0x38, 0x99, 0x1E, 0x43, 0xC1, 0xDB, 0xF4,
    0x0C, 0xA3, 0xA5, 0x5D, 0x33, 0x5F, 0x1F, 0x99, 0x0D, 0xAE, 0xF7, 0x81,
    0xD2, 0x8F, 0x30, 0x67, 0xCE, 0x44, 0x88, 0x24, 0xC2, 0x77, 0x3D, 0x1D,
    0xC5, 0xF7, 0x07, 0xE1, 0x64, 0x41, 0x89, 0x7E, 0x22, 0x9F, 0x2B, 0x93,
    0xA0, 0x95, 0xCB, 0x03, 0xD6, 0x73, 0x57, 0x0B, 0x32, 0x8D, 0xA5, 0x28,
    0x2B, 0xD1, 0xBA, 0x06, 0x89, 0xE6, 0x68, 0xDB, 0xDE, 0x8E, 0x3A, 0x2A,
    0xA9, 0xBF, 0x73, 0xAC, 0x33, 0xB8, 0x6F, 0x49, 0x8E, 0x09, 0xA1, 0xE2,
    0x54, 0x96, 0x4E, 0x0D, 0x29, 0x47, 0xA2, 0x59, 0xAC, 0x86, 0x8B, 0xEE,
    0xF6, 0x5D, 0x14, 0x65, 0x32, 0xCB, 0xA9, 0xB9, 0x47, 0xE3, 0x8F, 0x5A,
    0x40, 0xF7, 0xF4, 0x67, 0xB7, 0x92, 0xFF, 0x53, 0x38, 0xA3, 0xC9, 0x5E,
    0xC6, 0xAC, 0xA9, 0x50, 0x65, 0x1F, 0x6A, 0x49, 0x2F, 0x22, 0x1D, 0xEC,
    0x5C, 0xA0, 0x22, 0xE1, 0x2B, 0x20, 0x74, 0x44, 0xB7, 0x1E, 0x72, 0x09
};

static const Cpa8U dp_3072[] = {
    0x85, 0x1E, 0x35, 0x4F, 0x9C, 0xAF, 0x9B, 0xF7, 0xAF, 0xFE, 0xCC, 0xFA,
    0x67, 0x26, 0x4D, 0xDB, 0x43, 0x51, 0x5E, 0xAC, 0xF5, 0x72, 0x41, 0x27,
    0x0C, 0x66, 0x02, 0x87, 0x30, 0xF0, 0xD0, 0xE0, 0xEC, 0x42, 0xA0, 0x01,
    0x25, 0x98, 0xEB, 0x51, 0xC3, 0xCC, 0x68, 0x85, 0x4E, 0xD4, 0x1B, 0x2C,
    0x51, 0x2F, 0xCF, 0x53, 0x22, 0x09, 0xCF, 0x4C, 0x5E, 0xAD, 0x4D, 0x83,
    0x39, 0xFA, 0x1C, 0x88, 0xED, 0x66, 0xAE, 0x87, 0x9A, 0xE0, 0xBA, 0xD4,
    0x1E, 0xD2, 0x63, 0x06, 0x5E, 0xB6, 0xBD, 0xEE, 0x11, 0xE1, 0x3D, 0x44,
    0x6E, 0x92, 0x88, 0x15, 0x58, 0x06, 0xAB, 0x84, 0x83, 0x95, 0x81, 0x62,
    0xE7, 0x9C, 0x1B, 0x99, 0xD4, 0x51, 0x3E, 0x37, 0x2B, 0x34, 0xBC, 0x17,
    0xA0, 0xBB, 0x2F, 0x3A, 0xDE, 0xE6, 0xDF, 0xE8, 0x4B, 0xD2, 0xA8, 0x9E,
    0x6C, 0x73, 0xE0, 0xC1, 0xA4, 0xA7, 0x07, 0x61, 0x12, 0x20, 0x03, 0x41,
    0xF5, 0x79, 0xEB, 0x40, 0x76, 0x92, 0x04, 0x47, 0x8D, 0x9C, 0x87, 0x2D,
    0xD9, 0x1A, 0x12, 0x65, 0xAD, 0x10, 0x70, 0x77, 0x6B, 0x1B, 0x5A, 0x3A,
    0x9B, 0xB3, 0x52, 0xF2, 0xFC, 0xDC, 0x73, 0x25, 0x33, 0x06, 0xBD, 0x5C,
    0x22, 0xCA, 0x50, 0x90, 0x94, 0xD3, 0x12, 0x8B, 0x1D, 0x2C, 0x63, 0xC2,
    0x26, 0xDA, 0x9A, 0x75, 0x22, 0x0E, 0x0F, 0xFA, 0x85, 0xE9, 0x4D, 0xB7
};

static const Cpa8U dq_3072[] = {
    0x85, 0x1E, 0x2E, 0xAA, 0x2D, 0xCF, 0x64, 0x31, 0x76, 0x39, 0x9A, 0x33,
    0x6B, 0x19, 0x4B, 0x1C, 0xC9, 0x4B, 0x0B, 0xF4, 0xF5, 0x01, 0x29, 0x40,
    0xFE, 0x31, 0x9D, 0xEC, 0xBF, 0x50, 0xD4, 0xBE, 0x4D, 0x91, 0xD7, 0x0A,
    0x04, 0x94, 0x36, 0x19, 0xEF, 0x87, 0x48, 0xA6, 0x39, 0xE7, 0x92, 0x8C,
    0x2C, 0x09, 0xAF, 0x91, 0x9D, 0x9E, 0x14, 0x8E, 0x20, 0x26, 0x8A, 0x7B,
    0xCB, 0x15, 0x2D, 0x70, 0x6C, 0xF3, 0x5F, 0x38, 0x3A, 0x3B, 0x8A, 0x75,
    0x0C, 0x99, 0x49, 0x9B, 0xEE, 0x63, 0xB1, 0x94, 0x2B, 0x32, 0x62, 0xB4,
    0xB5, 0xD0, 0x77, 0xD2, 0x2F, 0x9A, 0x60, 0x91, 0xD5, 0x38, 0x88, 0x9B,
    0xB0, 0x46, 0xB9, 0xC3, 0x8E, 0x3C, 0xD3, 0x30, 0x6A, 0x57, 0x41, 0x03,
    0x8F, 0x8C, 0xB2, 0xE5, 0x56, 0x17, 0xAD, 0x84, 0xC6, 0x0D, 0x6E, 0x1D,
    0x1A, 0xEF, 0x65, 0x58, 0xF4, 0x58, 0x85, 0x24, 0x6B, 0xDE, 0xAD, 0x39,
    0xDA, 0x7B, 0xF7, 0xBE, 0x09, 0x3A, 0x61, 0xC7, 0xB1, 0x3E, 0xA1, 0xF2,
    0xC9, 0x45, 0xA9, 0xA2, 0xFE, 0x17, 0xA8, 0x49, 0x8D, 0x91, 0xBD, 0x2F,
    0x46, 0x43, 0x6E, 0xB7, 0xC9, 0x2D, 0xDA, 0xFD, 0x08, 0xC9, 0x70, 0x31,
    0x1C, 0xA4, 0x84, 0x76, 0xF7, 0x1F, 0xC8, 0xB6, 0xDD, 0x86, 0x38, 0x81,
    0x69, 0x3A, 0xF0, 0xE2, 0x6F, 0x60, 0x36, 0x00, 0x2C, 0xC2, 0x77, 0xCB
};

static const Cpa8U p_3072[] = {
    0xc7, 0xad, 0x4f, 0xf7, 0x6b, 0x07, 0x69, 0xf3, 0x87, 0xfe, 0x33, 0x77,
    0x9a, 0xb9, 0x74, 0xc8, 0xe4, 0xfa, 0x0e, 0x03, 0x70, 0x2b, 0x61, 0xba,
    0x92, 0x99, 0x03, 0xca, 0xc9, 0x69, 0x39, 0x51, 0x62, 0x63, 0xf0, 0x01,
    0xb8, 0x65, 0x60, 0xfa, 0xa5, 0xb2, 0x9c, 0xc7, 0xf6, 0x3e, 0x28, 0xc2,
    0x79, 0xc7, 0xb6, 0xfc, 0xb3, 0x0e, 0xb6, 0xf2, 0x8e, 0x03, 0xf4, 0x44,
    0xd6, 0xf7, 0x2a, 0xcd, 0x64, 0x1a, 0x05, 0xcb, 0x68, 0x51, 0x18, 0x3e,
    0x2e, 0x3b, 0x94, 0x89, 0x8e, 0x12, 0x1c, 0xe5, 0x1a, 0xd1, 0xdb, 0xe6,
    0xa5, 0xdb, 0xcc, 0x20, 0x04, 0x0a, 0x01, 0x46, 0xc5, 0x60, 0x42, 0x14,
    0x5b, 0x6a, 0x29, 0x66, 0xbe, 0x79, 0xdd, 0x52, 0xc0, 0xcf, 0x1a, 0x23,
    0x71, 0x18, 0xc6, 0xd8, 0x4e, 0x5a, 0x4f, 0xdc, 0x71, 0xbb, 0xfc, 0xed,
    0xa2, 0xad, 0xd1, 0x22, 0x76, 0xfa, 0x8b, 0x11, 0x9b, 0x30, 0x04, 0xe2,
    0xf0, 0x36, 0xe0, 0xe0, 0xb1, 0xdb, 0x06, 0x6b, 0x54, 0x6a, 0xca, 0xc4,
    0xc5, 0xa7, 0x1b, 0x98, 0x83, 0x98, 0xa8, 0xb3, 0x20, 0xa9, 0x07, 0x57,
    0xe9, 0x8c, 0xfc, 0x6c, 0x7b, 0x4a, 0xac, 0xb7, 0xcc, 0x8a, 0x1c, 0x0a,
    0x34, 0x2f, 0x78, 0xd8, 0xdf, 0x3c, 0x9b, 0xd0, 0xab, 0xc2, 0x95, 0xa3,
    0x3a, 0x47, 0xe7, 0xaf, 0xb3, 0x15, 0x17, 0xf7, 0xc8, 0xdd, 0xf4, 0x93
};

static const Cpa8U q_3072[] = {
    0xc7, 0xad, 0x45, 0xff, 0x44, 0xb7, 0x16, 0x4a, 0x31, 0x56, 0x67, 0x4d,
    0x20, 0xa5, 0xf0, 0xab, 0x2d, 0xf0, 0x91, 0xef, 0x6f, 0x81, 0xbd, 0xe1,
    0x7d, 0x4a, 0x6c, 0xe3, 0x1e, 0xf9, 0x3f, 0x1d, 0x74, 0x5a, 0xc2, 0x8f,
    0x06, 0xde, 0x51, 0x26, 0xe7, 0x4a, 0xec, 0xf9, 0x56, 0xdb, 0x5b, 0xd2,
    0x42, 0x0e, 0x87, 0x5a, 0x6c, 0x6d, 0x1e, 0xd5, 0x30, 0x39, 0xcf, 0xb9,
    0xb0, 0x9f, 0xc4, 0x28, 0xa3, 0x6d, 0x0e, 0xd4, 0x57, 0x59, 0x4f, 0xaf,
    0x92, 0xe5, 0xee, 0x69, 0xe5, 0x95, 0x8a, 0x5e, 0x40, 0xcb, 0x94, 0x0f,
    0x10, 0xb8, 0xb3, 0xbb, 0x47, 0x67, 0x90, 0xda, 0xbf, 0xd4, 0xcc, 0xe9,
    0x88, 0x6a, 0x16, 0xa5, 0x55, 0x5b, 0x3c, 0xc8, 0x9f, 0x82, 0xe1, 0x85,
    0x57, 0x53, 0x0c, 0x58, 0x01, 0x23, 0x84, 0x47, 0x29, 0x14, 0x25, 0x2b,
    0xa8, 0x67, 0x18, 0x05, 0x6e, 0x84, 0xc7, 0xb6, 0xa1, 0xce, 0x03, 0xd6,
    0xc7, 0xb9, 0xf3, 0x9d, 0x0d, 0xd7, 0x92, 0xab, 0x89, 0xdd, 0xf2, 0xec,
    0x2d, 0xe8, 0x7e, 0x74, 0x7d, 0x23, 0x7c, 0x6e, 0x54, 0x5a, 0x9b, 0xc6,
    0xe9, 0x65, 0x26, 0x13, 0xad, 0xc4, 0xc8, 0x7b, 0x8d, 0x2e, 0x28, 0x49,
    0xaa, 0xf6, 0xc6, 0xb2, 0x72, 0xaf, 0xad, 0x12, 0x4c, 0x49, 0x54, 0xc2,
    0x1d, 0xd8, 0x69, 0x53, 0xa7, 0x10, 0x51, 0x00, 0x43, 0x23, 0xb3, 0xb1
};

static const Cpa8U n_3072[] = {
    0x9B, 0xBE, 0xDF, 0xE1, 0x30, 0x2F, 0x46, 0x30, 0x29, 0xFA, 0x1A, 0x49,
    0xD8, 0x02, 0x96, 0x16, 0xC1, 0x94, 0x31, 0x5F, 0x0C, 0x7D, 0xE7, 0xC7,
    0xE3, 0x36, 0xA7, 0x99, 0x6A, 0xCF, 0x82, 0x38, 0xE9, 0x40, 0xAC, 0x56,
    0xC2, 0x10, 0x4C, 0xF9, 0x1F, 0x46, 0x3E, 0xA7, 0xF1, 0xDF, 0x07, 0x19,
    0xD1, 0xED, 0xB8, 0xF7, 0xBE, 0x7E, 0xB3, 0x6D, 0x00, 0x2F, 0x91, 0xB0,
    0x39, 0x98, 0x48, 0x5D, 0xA8, 0x17, 0x42, 0xF2, 0x4A, 0x45, 0x49, 0x2C,
    0xF5, 0x66, 0xAF, 0xB9, 0x9A, 0x89, 0x3D, 0x5A, 0xEB, 0x2B, 0xE5, 0x58,
    0xDD, 0x21, 0x77, 0xF8, 0x77, 0xB5, 0xFF, 0xCD, 0xAF, 0x38, 0xDA, 0x48,
    0x43, 0xC1, 0x02, 0x92, 0x5C, 0x0F, 0xAE, 0xE5, 0x87, 0xC2, 0x39, 0xCB,
    0x3F, 0x64, 0xDB, 0xF7, 0xA9, 0x0E, 0x68, 0xBC, 0xC8, 0x59, 0x8D, 0x60,
    0xBA, 0xDB, 0xCC, 0xB7, 0x7F, 0x79, 0x99, 0x96, 0x95, 0x1D, 0x42, 0x08,
    0x4A, 0x45, 0x05, 0xDC, 0xB9, 0xCD, 0x08, 0x90, 0x61, 0xB3, 0xD1, 0x32,
    0x88, 0x4C, 0x50, 0xB1, 0x8A, 0x30, 0x26, 0x3F, 0x66, 0xD6, 0x93, 0x2F,
    0x24, 0x0F, 0xF9, 0xD0, 0x79, 0x66, 0x1B, 0x8E, 0x4B, 0x47, 0x06, 0x97,
    0x79, 0x4F, 0x8D, 0xB5, 0x36, 0x65, 0xFE, 0xFE, 0xC9, 0xE0, 0x05, 0xB5,
    0x57, 0x8C, 0x4C, 0xD9, 0xAC, 0xD1, 0x8B, 0xEA, 0x61, 0x31, 0x44, 0x77,
    0x35, 0x7A, 0x84, 0xC0, 0x0E, 0x4E, 0xAA, 0x7D, 0x2D, 0x29, 0x06, 0x44,
    0x0C, 0xC2, 0xCA, 0xF3, 0xFB, 0xC0, 0xC3, 0x95, 0xB0, 0x17, 0x3E, 0xE7,
    0x8E, 0xFA, 0x64, 0xDA, 0x48, 0xB3, 0x2B, 0xAC, 0x21, 0x91, 0xA0, 0xCC,
    0x7F, 0x40, 0x31, 0x3D, 0x08, 0xE7, 0x01, 0xA3, 0x0C, 0x47, 0x7D, 0x14,
    0x88, 0xFC, 0x1D, 0x44, 0xAA, 0xD9, 0x1A, 0x36, 0x55, 0x8F, 0x65, 0x07,
    0xCA, 0x8A, 0xF9, 0x58, 0x59, 0xA8, 0x25, 0x62, 0x26, 0xF7, 0x48, 0x48,
    0x19, 0x9C, 0xE3, 0x49, 0x3C, 0x74, 0x10, 0xAC, 0x0C, 0xBC, 0xD9, 0x99,
    0x94, 0xC3, 0xC2, 0x36, 0x59, 0x21, 0x8A, 0xD4, 0x1A, 0xFE, 0x49, 0x1F,
    0xF3, 0x33, 0x3B, 0x90, 0xA0, 0xF6, 0x62, 0x0A, 0xA8, 0xBA, 0x8C, 0xA7,
    0xAB, 0xEA, 0x81, 0x59, 0x36, 0xF8, 0x68, 0xD1, 0x43, 0xCC, 0xFD, 0xE4,
    0xC8, 0xF1, 0x28, 0x2A, 0x8B, 0xD9, 0x05, 0x9D, 0x19, 0x4C, 0x87, 0x8D,
    0x52, 0xA1, 0x83, 0x38, 0xF5, 0xA8, 0xC3, 0xAF, 0x45, 0x2C, 0xB8, 0xF7,
    0xB6, 0xE1, 0x5B, 0x5A, 0xF2, 0x26, 0xAA, 0xB3, 0x99, 0x37, 0x23, 0x5F,
    0xF3, 0x76, 0x23, 0xF5, 0x4B, 0xDD, 0x2B, 0x02, 0x9D, 0x27, 0x74, 0xCC,
    0x5F, 0x9D, 0xA6, 0x05, 0x9D, 0x4A, 0x17, 0x10, 0x46, 0xB5, 0x86, 0xCB,
    0x38, 0x04, 0x61, 0x7D, 0x1A, 0x5C, 0xE4, 0x1F, 0xFC, 0x91, 0xE2, 0xA3
};

static const Cpa8U e_3072[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
};

static void makeParam1SmallerThanParam2(Cpa8U *param1,
                                        Cpa8U *param2,
                                        Cpa32U len,
                                        CpaBoolean msbSettingRequired)
{
    Cpa32U i = 0;
    int startLen = 0;
    if (msbSettingRequired == CPA_TRUE)
    {

        /*set startLen = 1 so that next for loop starts
         * at 1 rather than 0,
         * we handle element 0 here*/
        startLen = 1;
        /*Ignoring MSB, if param2 is less than param1, and param2 is not 0,
         * then make param1 to be smaller than param2, and we are done*/
        if (((param2[0] & (~MSB_SETTING)) <= (param1[0] & (~MSB_SETTING))) &&
            (param2[0] & (~MSB_SETTING)) != 0)
        {
            param1[0] = param2[0] - 1;
            return;
        }
        /*Ignoring MSB, if param2 is 0 then param1 needs to be zero with MSB
         * set and we check the next index*/
        else if ((param2[0] & (~MSB_SETTING)) == 0)
        {
            param1[i] = MSB_SETTING;
        }
        /*else Param1 is smaller than param2 so set i = len to skip next for
         * loop*/
        else
        {
            return;
        }
    }
    for (i = startLen; i < len; i++)
    {
        /*if param2 is less than param1, and param2 is not 0, then make param1
         * to be smaller than param2, and we are done*/
        if ((param2[i] <= param1[i]) && param2[i] != 0)
        {
            param1[i] = param2[i] - 1;
            break;
        }

        /*if param2 is 0 then param1 needs to be zero and we check the next
         * index*/
        else if (param2[i] == 0)
        {
            param1[i] = 0;
        }
        /*Param1 is smaller than param2 so we break*/
        else
        {
            break;
        }
    }
}

static CpaStatus setKptRsaDecryptOpData(
    Cpa32U node,
    CpaFlatBuffer inputData,
    CpaCyKptRsaDecryptOpData *pKptRsaDecOpdata)
{
    CpaFlatBuffer rsaPrivateKey = { 0 };
    CpaFlatBuffer wpkAndAuthTag = { 0 };
    Cpa8U authTag[AUTH_TAG_LEN] = { 0 };
    Cpa32U wpkSize = 0;
    CpaBoolean stat = CPA_TRUE;

    pKptRsaDecOpdata->pRecipientPrivateKey = qaeMemAllocNUMA(
        sizeof(CpaCyKptRsaPrivateKey *), node, BYTE_ALIGNMENT_64);
    if (NULL == pKptRsaDecOpdata->pRecipientPrivateKey)
    {
        PRINT_ERR(
            "qaeMemAllocNUMA pKptRsaDecOpdata->pRecipientPrivateKey error\n");
        return CPA_STATUS_FAIL;
    }

    rsaPrivateKey.dataLenInBytes =
        sizeof(qinv_3072) + sizeof(dp_3072) + sizeof(dq_3072) + sizeof(p_3072) +
        sizeof(q_3072) + sizeof(p_3072) * KEY_PAIRS_NUM;

    rsaPrivateKey.pData = qaeMemAlloc(rsaPrivateKey.dataLenInBytes);
    if (NULL == rsaPrivateKey.pData)
    {
        PRINT_ERR("qaeMemAlloc rsaPrivateKey error\n");
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->pRecipientPrivateKey));
        return CPA_STATUS_FAIL;
    }

    memset(rsaPrivateKey.pData, 0, rsaPrivateKey.dataLenInBytes);
    memcpy(rsaPrivateKey.pData, p_3072, sizeof(p_3072));

    memcpy(rsaPrivateKey.pData + sizeof(p_3072), q_3072, sizeof(q_3072));

    memcpy(rsaPrivateKey.pData + sizeof(p_3072) + sizeof(q_3072),
           dp_3072,
           sizeof(dp_3072));

    memcpy(rsaPrivateKey.pData + sizeof(p_3072) + sizeof(q_3072) +
               sizeof(dp_3072),
           dq_3072,
           sizeof(dq_3072));

    memcpy(rsaPrivateKey.pData + sizeof(p_3072) + sizeof(q_3072) +
               sizeof(dp_3072) + sizeof(dq_3072),
           qinv_3072,
           sizeof(qinv_3072));

    memcpy(rsaPrivateKey.pData + sizeof(p_3072) + sizeof(q_3072) +
               sizeof(dp_3072) + sizeof(dq_3072) + sizeof(qinv_3072) +
               sizeof(p_3072) * KEY_PAIRS_NUM - sizeof(e_3072),
           e_3072,
           sizeof(e_3072));

    wpkAndAuthTag.dataLenInBytes = rsaPrivateKey.dataLenInBytes + AUTH_TAG_LEN;
    wpkAndAuthTag.pData = qaeMemAlloc(wpkAndAuthTag.dataLenInBytes);
    if (NULL == wpkAndAuthTag.pData)
    {
        PRINT_ERR("qaeMemAlloc wpkAndAuthTag error\n");
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->pRecipientPrivateKey));
        qaeMemFree((void **)&rsaPrivateKey.pData);
        return CPA_STATUS_FAIL;
    }

    stat = encryptPrivateKey(rsaPrivateKey.pData,
                             rsaPrivateKey.dataLenInBytes,
                             (Cpa8U *)sampleSWK,
                             (Cpa8U *)iv,
                             sizeof(iv),
                             wpkAndAuthTag.pData,
                             &wpkSize,
                             authTag,
                             (Cpa8U *)aad,
                             sizeof(aad));
    if (CPA_FALSE == stat)
    {
        PRINT_ERR("encryptPrivateKey failed!\n");
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->pRecipientPrivateKey));
        qaeMemFree((void **)&rsaPrivateKey.pData);
        qaeMemFree((void **)&wpkAndAuthTag.pData);
        return CPA_STATUS_FAIL;
    }

    memcpy(wpkAndAuthTag.pData + wpkSize, authTag, AUTH_TAG_LEN);

    pKptRsaDecOpdata->inputData.dataLenInBytes = inputData.dataLenInBytes;
    pKptRsaDecOpdata->inputData.pData = (Cpa8U *)qaeMemAllocNUMA(
        inputData.dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == pKptRsaDecOpdata->inputData.pData)
    {
        PRINT_ERR("qaeMemAllocNUMA pKptRsaDecOpdata->inputData error\n");
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->pRecipientPrivateKey));
        qaeMemFree((void **)&rsaPrivateKey.pData);
        qaeMemFree((void **)&wpkAndAuthTag.pData);
        return CPA_STATUS_FAIL;
    }
    memcpy(pKptRsaDecOpdata->inputData.pData,
           inputData.pData,
           inputData.dataLenInBytes);

    pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRep2.privateKey
        .dataLenInBytes = wpkSize + AUTH_TAG_LEN;
    pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRep2.privateKey.pData =
        (Cpa8U *)qaeMemAllocNUMA(pKptRsaDecOpdata->pRecipientPrivateKey
                                     ->privateKeyRep2.privateKey.dataLenInBytes,
                                 node,
                                 BYTE_ALIGNMENT_64);
    if (NULL ==
        pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRep2.privateKey.pData)
    {
        PRINT_ERR("qaeMemAllocNUMA "
                  "pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRep2."
                  "privateKey error\n");
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->pRecipientPrivateKey));
        qaeMemFreeNUMA((void **)&(pKptRsaDecOpdata->inputData.pData));
        qaeMemFree((void **)&rsaPrivateKey.pData);
        qaeMemFree((void **)&wpkAndAuthTag.pData);
        return CPA_STATUS_FAIL;
    }
    memcpy(
        pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRep2.privateKey.pData,
        wpkAndAuthTag.pData,
        wpkSize + AUTH_TAG_LEN);

    pKptRsaDecOpdata->pRecipientPrivateKey->privateKeyRepType =
        CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    pKptRsaDecOpdata->pRecipientPrivateKey->version =
        CPA_CY_RSA_VERSION_TWO_PRIME;

    qaeMemFree((void **)&rsaPrivateKey.pData);
    qaeMemFree((void **)&wpkAndAuthTag.pData);

    return CPA_STATUS_SUCCESS;
}

static CpaStatus swRsaSampleEnc(CpaInstanceHandle cyInstHandle,
                                Cpa32U node,
                                CpaFlatBuffer inputData,
                                CpaFlatBuffer *pOutputData)
{

    CpaStatus status = CPA_STATUS_SUCCESS;
    EVP_PKEY *pPubKey = NULL;
    EVP_PKEY_CTX *pCtx = NULL;
    int ret = 0;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    OSSL_PARAM_BLD *pBld = NULL;
    BIGNUM *pE_bn = NULL;
    BIGNUM *pN_bn = NULL;
    OSSL_PARAM *pParams = NULL;
#else
    CpaBoolean retStatus = CPA_TRUE;
    RSA *pKey = NULL;
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (CPA_STATUS_SUCCESS == status)
    {
        pBld = OSSL_PARAM_BLD_new();
        if ((NULL == pBld))
        {
            PRINT("OSSL_PARAM_BLD_new() failed \n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pN_bn = BN_new();
        pE_bn = BN_new();
        if ((NULL == pN_bn) || (NULL == pE_bn))
        {
            PRINT(" BN_new() failed \n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        BN_bin2bn(n_3072, sizeof(n_3072), pN_bn);
        OSSL_PARAM_BLD_push_BN(pBld, "n", pN_bn);
        BN_bin2bn(e_3072, sizeof(e_3072), pE_bn);
        OSSL_PARAM_BLD_push_BN(pBld, "e", pE_bn);

        pParams = OSSL_PARAM_BLD_to_param(pBld);
        if (NULL == pParams)
        {
            PRINT("OSSL_PARAM_BLD_to_param() failed \n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        pCtx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates generate key context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        EVP_PKEY_fromdata_init(pCtx);
        EVP_PKEY_fromdata(pCtx, &pPubKey, EVP_PKEY_PUBLIC_KEY, pParams);
        EVP_PKEY_CTX_free(pCtx);
        pCtx = EVP_PKEY_CTX_new(pPubKey, NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
#else
    if (CPA_STATUS_SUCCESS == status)
    {
        pKey = RSA_new();
        pPubKey = EVP_PKEY_new();
        if (NULL == pKey)
        {
            PRINT("RSA_new() failed \n");
            status = CPA_STATUS_FAIL;
        }
        else if (NULL == pPubKey)
        {
            PRINT("EVP_PKEY_new() failed");
            RSA_free(pKey);
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        /*-----set public key with n and e-----*/
        retStatus = RSA_set0_key(pKey,
                                 BN_bin2bn(n_3072, sizeof(n_3072), NULL),
                                 BN_bin2bn(e_3072, sizeof(e_3072), NULL),
                                 NULL);
        if (CPA_TRUE != retStatus)
        {
            PRINT_ERR("RSA_set0_key failed \n");
            RSA_free(pKey);
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        EVP_PKEY_assign_RSA(pPubKey, pKey);
        pCtx = EVP_PKEY_CTX_new(pPubKey, NULL);
        if (NULL == pCtx)
        {
            PRINT_ERR("Allocates public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (EVP_PKEY_encrypt_init(pCtx) > 0)
        {
            EVP_PKEY_CTX_ctrl_str(pCtx, "rsa_padding_mode", "none");
        }
        else
        {
            PRINT_ERR("Initializes a public key algorithm context failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
    if (CPA_STATUS_SUCCESS == status)
    {
        ret = EVP_PKEY_encrypt(pCtx,
                               pOutputData->pData,
                               (size_t *)&(pOutputData->dataLenInBytes),
                               inputData.pData,
                               inputData.dataLenInBytes);

        if ((ret <= 0) || (0 == pOutputData->dataLenInBytes) ||
            (pOutputData->dataLenInBytes >
             (KEY_SIZE_3072_BIT + BITS_IN_BYTE - 1) / BITS_IN_BYTE))
        {
            PRINT_ERR("EVP_PKEY_encrypt failed!\n");
            status = CPA_STATUS_FAIL;
        }
    }
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (NULL != pBld)
    {
        OSSL_PARAM_BLD_free(pBld);
    }
    if (NULL != pN_bn)
    {
        BN_free(pN_bn);
    }
    if (NULL != pE_bn)
    {
        BN_free(pE_bn);
    }
    if (NULL != pParams)
    {
        OSSL_PARAM_free(pParams);
    }
    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
#else
    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
    if (NULL != pPubKey)
    {
        EVP_PKEY_free(pPubKey);
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */

    return status;
}
static CpaStatus rsaSampleEnc(CpaInstanceHandle cyInstHandle,
                              Cpa32U node,
                              CpaFlatBuffer inputData,
                              CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyRsaEncryptOpData encryptOpData = { 0 };

    encryptOpData.inputData.dataLenInBytes = inputData.dataLenInBytes;
    encryptOpData.inputData.pData = (Cpa8U *)qaeMemAllocNUMA(
        inputData.dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == encryptOpData.inputData.pData)
    {
        PRINT_ERR("Failed to allocate mem for encrypt input data\n");
        return CPA_STATUS_FAIL;
    }
    memset(encryptOpData.inputData.pData, 0, inputData.dataLenInBytes);
    memcpy(encryptOpData.inputData.pData,
           inputData.pData,
           inputData.dataLenInBytes);

    encryptOpData.pPublicKey = qaeMemAlloc(sizeof(CpaCyRsaPublicKey));
    if (NULL == encryptOpData.pPublicKey)
    {
        PRINT_ERR("Failed to allocate mem for RSA public key\n");
        qaeMemFreeNUMA((void **)&encryptOpData.inputData.pData);
        return CPA_STATUS_FAIL;
    }
    memset(encryptOpData.pPublicKey, 0, sizeof(CpaCyRsaPublicKey));

    encryptOpData.pPublicKey->modulusN.dataLenInBytes = sizeof(n_3072);
    encryptOpData.pPublicKey->modulusN.pData =
        (Cpa8U *)qaeMemAllocNUMA(sizeof(n_3072), node, BYTE_ALIGNMENT_64);
    if (NULL == encryptOpData.pPublicKey->modulusN.pData)
    {
        PRINT_ERR("Failed to allocate mem for modulusN\n");
        qaeMemFreeNUMA((void **)&encryptOpData.inputData.pData);
        qaeMemFree((void **)&encryptOpData.pPublicKey);
        return CPA_STATUS_FAIL;
    }
    memset(encryptOpData.pPublicKey->modulusN.pData, 0, sizeof(n_3072));
    memcpy(encryptOpData.pPublicKey->modulusN.pData, n_3072, sizeof(n_3072));

    encryptOpData.pPublicKey->publicExponentE.dataLenInBytes = sizeof(e_3072);
    encryptOpData.pPublicKey->publicExponentE.pData =
        (Cpa8U *)qaeMemAllocNUMA(sizeof(e_3072), node, BYTE_ALIGNMENT_64);
    if (NULL == encryptOpData.pPublicKey->publicExponentE.pData)
    {
        PRINT_ERR("Failed to allocate mem for publicExponentE\n");
        qaeMemFreeNUMA((void **)&encryptOpData.pPublicKey->modulusN.pData);
        qaeMemFreeNUMA((void **)&encryptOpData.inputData.pData);
        qaeMemFree((void **)&encryptOpData.pPublicKey);
        return CPA_STATUS_FAIL;
    }
    memset(encryptOpData.pPublicKey->publicExponentE.pData, 0, sizeof(e_3072));
    memcpy(encryptOpData.pPublicKey->publicExponentE.pData,
           e_3072,
           sizeof(e_3072));

    status = cpaCyRsaEncrypt(cyInstHandle,
                             NULL, /*callback function not required*/
                             NULL, /*opaque data not required*/
                             &encryptOpData,
                             pOutputData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("RSA encrypt failed\n");
    }

    qaeMemFreeNUMA((void **)&encryptOpData.pPublicKey->publicExponentE.pData);
    qaeMemFreeNUMA((void **)&encryptOpData.pPublicKey->modulusN.pData);
    qaeMemFreeNUMA((void **)&encryptOpData.inputData.pData);
    qaeMemFree((void **)&encryptOpData.pPublicKey);

    return status;
}

static CpaStatus kptRsaSampleDec(CpaInstanceHandle cyInstHandle,
                                 Cpa32U node,
                                 CpaFlatBuffer inputData,
                                 CpaFlatBuffer *pOutputData)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyKptRsaDecryptOpData kptRsaDecOpdata = { 0 };
    CpaCyKptUnwrapContext kptUnwrapCtx = { 0 };
    CpaCyKptKeyManagementStatus kptStatus = CPA_CY_KPT_SUCCESS;

    status = encryptAndLoadSWK(
        cyInstHandle, node, &kptUnwrapCtx.kptHandle, (Cpa8U *)sampleSWK);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("encrypt And Load SWK failed!\n");
        return status;
    }

    memcpy(kptUnwrapCtx.iv, iv, sizeof(iv));
    memcpy(kptUnwrapCtx.additionalAuthData, aad, sizeof(aad));
    kptUnwrapCtx.aadLenInBytes = sizeof(aad);

    status = setKptRsaDecryptOpData(node, inputData, &kptRsaDecOpdata);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("setKptRsaDecryptOpData failed!\n");
        cpaCyKptDeleteKey(cyInstHandle, kptUnwrapCtx.kptHandle, &kptStatus);
        return status;
    }

    pOutputData->dataLenInBytes = KEY_SIZE_3072_BIT / BITS_IN_BYTE;
    pOutputData->pData = (Cpa8U *)qaeMemAllocNUMA(
        pOutputData->dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == pOutputData->pData)
    {
        PRINT_ERR("qaeMemAllocNUMA pOutputData failed\n");
        cpaCyKptDeleteKey(cyInstHandle, kptUnwrapCtx.kptHandle, &kptStatus);
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.inputData.pData));
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.pRecipientPrivateKey
                                      ->privateKeyRep2.privateKey.pData));
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.pRecipientPrivateKey));
        return CPA_STATUS_FAIL;
    }

    status = cpaCyKptRsaDecrypt(cyInstHandle,
                                NULL, /*callback function not required*/
                                NULL, /*opaque data not required*/
                                &kptRsaDecOpdata,
                                pOutputData,
                                &kptUnwrapCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyKptRsaDecrypt failed, status =%d \n", status);
        cpaCyKptDeleteKey(cyInstHandle, kptUnwrapCtx.kptHandle, &kptStatus);
        qaeMemFreeNUMA((void **)&(pOutputData->pData));
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.inputData.pData));
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.pRecipientPrivateKey
                                      ->privateKeyRep2.privateKey.pData));
        qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.pRecipientPrivateKey));
        return status;
    }

    printf("key deletion, handle is 0x%lx \n", kptUnwrapCtx.kptHandle);
    status =
        cpaCyKptDeleteKey(cyInstHandle, kptUnwrapCtx.kptHandle, &kptStatus);
    if ((CPA_STATUS_SUCCESS != status) || (CPA_CY_KPT_SUCCESS != kptStatus))
    {
        PRINT_ERR("Delete SWK failed with status: %d,kpt2Status: %d.\n",
                  status,
                  kptStatus);
        qaeMemFreeNUMA((void **)&(pOutputData->pData));
        status = CPA_STATUS_FAIL;
    }

    qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.inputData.pData));
    qaeMemFreeNUMA((void **)&(
        kptRsaDecOpdata.pRecipientPrivateKey->privateKeyRep2.privateKey.pData));
    qaeMemFreeNUMA((void **)&(kptRsaDecOpdata.pRecipientPrivateKey));

    return status;
}

CpaStatus kptRsaOp(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle cyInstHandle = 0;
    CpaCyCapabilitiesInfo pCapInfo = { 0 };
    CpaInstanceInfo2 instanceInfo = { 0 };
    CpaFlatBuffer rsaEncInputData = { 0 };
    CpaFlatBuffer rsaEncOutputData = { 0 };
    CpaFlatBuffer kptRsaDecOutputData = { 0 };
    Cpa32U node = 0;
    Cpa16U num = 0;

    cpaCyGetNumInstances(&num);
    sampleCyGetInstance(&cyInstHandle);
    if (cyInstHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCyInstanceGetInfo2(cyInstHandle, &instanceInfo);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("%s::%d cpaCyInstanceGetInfo2 failed", __func__, __LINE__);
        return CPA_STATUS_FAIL;
    }

    status = queryCapabilitiesForKpt(cyInstHandle, instanceInfo, &pCapInfo);
    if ((CPA_STATUS_SUCCESS != status) ||
        ((CPA_STATUS_SUCCESS == status) && !pCapInfo.kptSupported))
    {
        return status;
    }

    status = cpaCyStartInstance(cyInstHandle);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyStartInstance failed\n");
        return status;
    }
    status = cpaCySetAddressTranslation(cyInstHandle, sampleVirtToPhys);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySetAddressTranslation failed\n");
        cpaCyStopInstance(cyInstHandle);
        return status;
    }
    sampleCyStartPolling(cyInstHandle);

    node = instanceInfo.nodeAffinity;

    rsaEncInputData.dataLenInBytes =
        (KEY_SIZE_3072_BIT + BITS_IN_BYTE - 1) / BITS_IN_BYTE;
    rsaEncInputData.pData = (Cpa8U *)qaeMemAllocNUMA(
        rsaEncInputData.dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == rsaEncInputData.pData)
    {
        PRINT_ERR("qaeMemAlloc inputData->pData error\n");
        sampleCyStopPolling();
        cpaCyStopInstance(cyInstHandle);
        return CPA_STATUS_FAIL;
    }
    rsaEncOutputData.dataLenInBytes =
        (KEY_SIZE_3072_BIT + BITS_IN_BYTE - 1) / BITS_IN_BYTE;
    rsaEncOutputData.pData = (Cpa8U *)qaeMemAllocNUMA(
        rsaEncOutputData.dataLenInBytes, node, BYTE_ALIGNMENT_64);
    if (NULL == rsaEncOutputData.pData)
    {
        PRINT_ERR("qaeMemAlloc pRsaEncOutputData->pData error\n");
        qaeMemFreeNUMA((void **)&rsaEncInputData.pData);
        sampleCyStopPolling();
        cpaCyStopInstance(cyInstHandle);
        return CPA_STATUS_FAIL;
    }
    memset(rsaEncOutputData.pData, 0, rsaEncOutputData.dataLenInBytes);

    PRINT("Generate random data for RSA encryption\n");
    genRandomData(rsaEncInputData.pData, rsaEncInputData.dataLenInBytes);
    makeParam1SmallerThanParam2(
        rsaEncInputData.pData, (Cpa8U *)n_3072, sizeof(n_3072), CPA_FALSE);
    hexLog(rsaEncInputData.pData,
           rsaEncInputData.dataLenInBytes,
           "encrypt input data");

    if (CPA_TRUE == pCapInfo.rsaSupported)
    {
        PRINT("Calling rsaSampleEnc : Encrypt input data\n");
        status = rsaSampleEnc(
            cyInstHandle, node, rsaEncInputData, &rsaEncOutputData);
    }
    else
    {
        PRINT("Calling swRsaSampleEnc : Encrypt input data\n");
        status = swRsaSampleEnc(
            cyInstHandle, node, rsaEncInputData, &rsaEncOutputData);
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("RSA encryption failed, status = %d\n", status);
        qaeMemFreeNUMA((void **)&rsaEncInputData.pData);
        qaeMemFreeNUMA((void **)&rsaEncOutputData.pData);
        sampleCyStopPolling();
        cpaCyStopInstance(cyInstHandle);
        return status;
    }
    hexLog(rsaEncOutputData.pData,
           rsaEncOutputData.dataLenInBytes,
           "RSA encrypted data");

    PRINT("calling kptRsaSampleDec : Decrypt encrypted data\n");
    status = kptRsaSampleDec(
        cyInstHandle, node, rsaEncOutputData, &kptRsaDecOutputData);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("kptRsaSampleDec not a success, status = %d\n", status);
        qaeMemFreeNUMA((void **)&rsaEncInputData.pData);
        qaeMemFreeNUMA((void **)&rsaEncOutputData.pData);
        sampleCyStopPolling();
        cpaCyStopInstance(cyInstHandle);
        return status;
    }

    hexLog(kptRsaDecOutputData.pData,
           kptRsaDecOutputData.dataLenInBytes,
           "KPT RSA decrypted data");

    if (memcmp(rsaEncInputData.pData,
               kptRsaDecOutputData.pData,
               kptRsaDecOutputData.dataLenInBytes) != 0)
    {
        PRINT_ERR("RSA match error\n");
        qaeMemFreeNUMA((void **)&rsaEncInputData.pData);
        qaeMemFreeNUMA((void **)&rsaEncOutputData.pData);
        qaeMemFreeNUMA((void **)&kptRsaDecOutputData.pData);
        sampleCyStopPolling();
        cpaCyStopInstance(cyInstHandle);
        return CPA_STATUS_FAIL;
    }

    PRINT("RSA match succeeded\n");

    qaeMemFreeNUMA((void **)&rsaEncInputData.pData);
    qaeMemFreeNUMA((void **)&rsaEncOutputData.pData);
    qaeMemFreeNUMA((void **)&kptRsaDecOutputData.pData);
    sampleCyStopPolling();
    cpaCyStopInstance(cyInstHandle);

    return status;
}
