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
 * @file  kpt_sample_common.h
 *
 *****************************************************************************/
#ifndef __KPT_SAMPLE_COMMON_H__
#define __KPT_SAMPLE_COMMON_H__

#include "cpa.h"
#include "cpa_cy_kpt.h"

#include "cpa_sample_utils.h"

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

#define AUTH_TAG_LEN 16
#define PER_PART_PKEY_E_SIZE 8
#define KEY_PROVISION_RETRY_TIMES_LIMIT 20
#define SWK_LEN_IN_BYTES 32
#define UPPER_HALF_OF_REGISTER 32
#define BUS_DIGIT 8
#define DEVICE_DIGIT 3
#define FUNCTION_DIGIT 7

CpaStatus encryptAndLoadSWK(CpaInstanceHandle instanceHandle,
                            Cpa32U node,
                            CpaCyKptHandle *kptKeyHandle,
                            Cpa8U *sampleSWK);

CpaBoolean encryptPrivateKey(Cpa8U *pPrivateKey,
                             Cpa32U privateKeyLength,
                             Cpa8U *pSWK,
                             Cpa8U *pIv,
                             Cpa32U ivLength,
                             Cpa8U *pWrappedPrivateKey,
                             Cpa32U *pWPKLength,
                             Cpa8U *pAuthTag,
                             Cpa8U *pAad,
                             Cpa32U aadLenInBytes);

void genRandomData(Cpa8U *pWriteRandData, Cpa32U lengthOfRand);

CpaStatus queryCapabilitiesForKpt(CpaInstanceHandle cyInstHandle,
                                  CpaInstanceInfo2 instanceInfo,
                                  CpaCyCapabilitiesInfo *pCapInfo);

#endif
