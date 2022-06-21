/***************************************************************************
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
 * @file sal_statistics.h
 *
 * @ingroup SalStats
 *
 * @description
 *     Statistics related defines, structures and functions
 *
 *****************************************************************************/

#ifndef SAL_STATISTICS_H
#define SAL_STATISTICS_H

/*
 * Config values names for statistics
 */
#define SAL_STATS_CFG_ENABLED "statsGeneral"
/**< Config value name for enabling/disabling statistics */
#define SAL_STATS_CFG_DC "statsDc"
/**< Config value name for enabling/disabling Compression statistics */
#define SAL_STATS_CFG_DH "statsDh"
/**< Config value name for enabling/disabling Diffie-Helman statistics */
#define SAL_STATS_CFG_DRBG "statsDrbg"
/**< Config value name for enabling/disabling DRBG statistics */
#define SAL_STATS_CFG_DSA "statsDsa"
/**< Config value name for enabling/disabling DSA statistics */
#define SAL_STATS_CFG_ECC "statsEcc"
/**< Config value name for enabling/disabling ECC statistics */
#define SAL_STATS_CFG_KEYGEN "statsKeyGen"
/**< Config value name for enabling/disabling Key Gen statistics */
#define SAL_STATS_CFG_LN "statsLn"
/**< Config value name for enabling/disabling Large Number statistics */
#define SAL_STATS_CFG_PRIME "statsPrime"
/**< Config value name for enabling/disabling Prime statistics */
#define SAL_STATS_CFG_RSA "statsRsa"
/**< Config value name for enabling/disabling RSA statistics */
#define SAL_STATS_CFG_SYM "statsSym"
/**< Config value name for enabling/disabling Symmetric Crypto statistics */
#define SAL_STATS_CFG_MISC "statsMisc"
/**< Config value name for enabling/disabling Miscellaneous error statistics */

#define SAL_STATS_SYM 0
#define SAL_STATS_DSA 1
#define SAL_STATS_DSA2 2
#define SAL_STATS_RSA 3
#define SAL_STATS_DH 4
#define SAL_STATS_KEYGEN 5
#define SAL_STATS_LN 6
#define SAL_STATS_PRIME 7
#define SAL_STATS_ECC 8
#define SAL_STATS_ECDH 9
#define SAL_STATS_ECDSA 10
#define SAL_STATS_MISC 11
/**< Numeric values for crypto statistics */

#define SAL_STATISTICS_STRING_OFF "0"
/**< String representing the value for disabled statistics */

/**
*****************************************************************************
* @ingroup SalStats
*      Structure describing stats enabled/disabled in the system
*
* @description
*      Structure describing stats enabled/disabled in the system
*
*****************************************************************************/
typedef struct sal_statistics_collection_s
{
    CpaBoolean bStatsEnabled;
    /**< If CPA_TRUE then statistics functionality is enabled */
    CpaBoolean bDcStatsEnabled;
    /**< If CPA_TRUE then Compression statistics are enabled */
    CpaBoolean bDhStatsEnabled;
    /**< If CPA_TRUE then Diffie-Helman statistics are enabled */
    CpaBoolean bDsaStatsEnabled;
    /**< If CPA_TRUE then DSA statistics are enabled */
    CpaBoolean bEccStatsEnabled;
    /**< If CPA_TRUE then ECC statistics are enabled */
    CpaBoolean bKeyGenStatsEnabled;
    /**< If CPA_TRUE then Key Gen statistics are enabled */
    CpaBoolean bLnStatsEnabled;
    /**< If CPA_TRUE then Large Number statistics are enabled */
    CpaBoolean bPrimeStatsEnabled;
    /**< If CPA_TRUE then Prime statistics are enabled */
    CpaBoolean bRsaStatsEnabled;
    /**< If CPA_TRUE then RSA statistics are enabled */
    CpaBoolean bSymStatsEnabled;
    /**< If CPA_TRUE then Symmetric Crypto statistics are enabled */
    CpaBoolean bMiscStatsEnabled;
    /**< If CPA_TRUE then Miscellaneous error statistics are enabled */
} sal_statistics_collection_t;

/**
 ******************************************************************************
 * @ingroup SalStats
 *
 * @description
 *      Initializes structure describing which statistics
 *      are enabled for the acceleration device.
 *
 * @param[in]  device             Pointer to an acceleration device structure
 *
 * @retval  CPA_STATUS_SUCCESS          Operation successful
 * @retval  CPA_STATUS_INVALID_PARAM    Invalid param provided
 * @retval  CPA_STATUS_RESOURCE         Memory alloc failed
 * @retval  CPA_STATUS_FAIL             Operation failed
 *
 ******************************************************************************/
CpaStatus SalStatistics_InitStatisticsCollection(icp_accel_dev_t *device);

/**
 ******************************************************************************
 * @ingroup SalStats
 *
 * @description
 *      Cleans structure describing which statistics
 *      are enabled for the acceleration device.
 *
 * @param[in]  device             Pointer to an acceleration device structure
 *
 * @retval  CPA_STATUS_SUCCESS          Operation successful
 * @retval  CPA_STATUS_INVALID_PARAM    Invalid param provided
 * @retval  CPA_STATUS_FAIL             Operation failed
 *
 ******************************************************************************/
CpaStatus SalStatistics_CleanStatisticsCollection(icp_accel_dev_t *device);

#if defined(COUNTERS) && !defined(DISABLE_STATS)
/* Type of the RSA request */
typedef enum
{
    LAC_RSA_ENCRYPT_REQUEST = 1,
    LAC_RSA_DECRYPT_REQUEST,
    LAC_RSA_KEYGEN_REQUEST
} rsa_request_type_t;

/* Type of the DH request */
typedef enum
{
    LAC_DH_PHASE1_REQUEST = 1,
    LAC_DH_PHASE2_REQUEST,
} dh_request_type_t;

/* Type of the DSA request */
typedef enum
{
    LAC_DSA_GEN_P_REQUEST = 1,
    LAC_DSA_GEN_G_REQUEST,
    LAC_DSA_GEN_Y_REQUEST,
    LAC_DSA_SIGN_R_REQUEST,
    LAC_DSA_SIGN_S_REQUEST,
    LAC_DSA_SIGN_RS_REQUEST,
    LAC_DSA_VERIFY_REQUEST
} dsa_request_type_t;

/* Type of the ECDSA request */
typedef enum
{
    LAC_ECDSA_SIGN_R_REQUEST = 1,
    LAC_ECDSA_SIGN_S_REQUEST,
    LAC_ECDSA_SIGN_RS_REQUEST,
    LAC_ECDSA_VERIFY_REQUEST
} ecdsa_request_type_t;

/* Type of the ECC request */
typedef enum
{
    LAC_ECC_POINT_MULTIPLY_REQUEST = 1,
    LAC_ECC_POINT_VERIFY_REQUEST,
} ecc_request_type_t;

/* Type of the Large Number request */
typedef enum
{
    LAC_LN_MODEXP_REQUEST = 1,
    LAC_LN_MODINV_REQUEST,
} ln_request_type_t;
#endif

#endif
