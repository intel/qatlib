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
 * @file cpa_sample_code_crypto_utils.h
 *
 * @ingroup cryptoThreads
 *
 * @description
 * Contains function prototypes and #defines used by crypto thread functions
 *
 ***************************************************************************/
#ifndef _CRYPTO_UTILS_H_
#define _CRYPTO_UTILS_H_
#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_im.h"
#include "cpa_cy_key.h"
#include "qat_perf_utils.h"
#include "cpa_sample_code_utils.h"
#include "cpa_sample_code_framework.h"

#ifdef SC_SM2_ENABLED
#include "cpa_cy_ecsm2.h"
#endif /* SC_SM2_ENABLED */

#ifdef USER_SPACE
#include <sched.h>
#endif


#ifdef POLL_INLINE
extern Cpa32U asymPollingInterval_g;
#endif
extern unsigned long long timeStampTime_g;
extern Cpa32U busyLoopMethod_g;
extern volatile CpaBoolean cy_service_started_g;
extern CpaBoolean timeStampInLoop;

/*
******************************************************************************
* General performance code settings
******************************************************************************
*/
#define MIN_CY_BUFFERS (20)
#define MIN_SYM_LOOPS (1)
#define MIN_ASYM_LOOPS (1)
#define DEFAULT_CY_BUFFERS (20)
#define DEFAULT_SYM_LOOPS (5000)
#define DEFAULT_ASYM_LOOPS (5000)
#define DEFAULT_WIRELESS_FIRMWARE (0)
#define DEFAULT_INCLUDE_WIRELESS_ALGS (1)
#define WIRELESS_PACKET_LIMIT (4)
#define SINGLE_OPERATION (1)

#define REMOVE_SESSION_WAIT (50)

/* KPT Stolen Key Test */

#define CY_API_VERSION_AT_LEAST(major, minor)                                  \
    (CPA_CY_API_VERSION_NUM_MAJOR > major ||                                   \
     (CPA_CY_API_VERSION_NUM_MAJOR == major &&                                 \
      CPA_CY_API_VERSION_NUM_MINOR >= minor))

#if CY_API_VERSION_AT_LEAST(3, 0)
#include "cpa_cy_kpt.h"
#endif

/*Each buffer list used in crypto performance code uses NUM_UNCHAINED_BUFFERS*/
#define NUM_UNCHAINED_BUFFERS (1)

/*number of times to retry before having a break from submitting requests*/
#define RETRY_LIMIT (100)
#define NUM_BITS_IN_BYTE (8)

/*used to set MSB of a byte, some of the QA API structures require this*/
#define MSB_SETTING (0x80)

/*define minimum number of asymmetric submission per thread that
 * results in an accurate operations per second calculation +/- 1%*/
#define ASYM_THROUGHPUT_MIN_SUBMISSIONS (10000)

/*PACKET_IMIX is an average of a mix of buffer sizes.
 * This is used to indicate to the crypto thread code that we want to test
 * a mix of buffersizes. This mix is based on:
 * 40% 64 Byte buffers
 * 20% 752 Byte buffers
 * 35% 1504 Byte buffers
 * 5% 8892 Byte buffers
 * */
/*PACKET_IMIX is the average size in the comment above*/
#define PACKET_IMIX (0)

/* NUM_PACKETS_IMIX specifies the number of packets that constitute IMIX */
#define NUM_PACKETS_IMIX (20)

/*number of buffers per buffer list
 * DP API in performance sample code can use flat buffers while the trad API
 * uses scatter gather lists and requires at least 1 CpaFlatBuffer in a list
 * this setting determines weather DP API uses flat buffer or CpaFlatBuffer*/
#define DEFAULT_CPA_FLAT_BUFFERS_PER_LIST (0)

#define CHECK_AND_STOPCYSERVICES()                                             \
    if (cy_service_started_g == CPA_TRUE)                                      \
    {                                                                          \
        stopCyServices();                                                      \
    }

#define DECLARE_IA_CYCLE_COUNT_VARIABLES()                                     \
    Cpa32U submissions = 0;                                                    \
    Cpa32U staticAssign = 0;                                                   \
    Cpa32U busyLoopCount = 0;                                                  \
    Cpa32U busyLoopValue = busyLoopCounter_g;                                  \
    perf_cycles_t startBusyLoop = 0, endBusyLoop = 0;                          \
    Cpa32U numBusyLoops = 0;                                                   \
    Cpa32U index = 0;                                                          \
    perf_cycles_t timeStampTime[10] = {0};                                     \
    perf_cycles_t timeStamp2 = 0;

#define BUSY_LOOP()                                                            \
    submissions++;                                                             \
    if (timeStampInLoop)                                                       \
    {                                                                          \
        if (submissions % 100 == 0 && submissions <= 1000)                     \
        {                                                                      \
            timeStampTime[index++] = getTimeStampTime2();                      \
        }                                                                      \
    }                                                                          \
    if (submissions < (setup->performanceStats->numOperations >> 1))           \
    {                                                                          \
        if (busyLoopMethod_g == 2)                                             \
        {                                                                      \
            setup->performanceStats->totalBusyLoopCycles +=                    \
                busyLoop2(busyLoopCounter_g, &staticAssign);                   \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            busyLoop(busyLoopCounter_g, &staticAssign);                        \
        }                                                                      \
        busyLoopCount++;                                                       \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        if (busyLoopMethod_g == 2)                                             \
        {                                                                      \
            busyLoop2(busyLoopCounter_g, &staticAssign);                       \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            busyLoop(busyLoopCounter_g, &staticAssign);                        \
            busyLoopCount++;                                                   \
        }                                                                      \
    }

#define IA_CYCLE_COUNT_CALCULATION()                                           \
    setup->performanceStats->busyLoopCount = busyLoopCount;                    \
    setup->performanceStats->busyLoopValue = busyLoopValue;                    \
                                                                               \
    if (timeStampInLoop)                                                       \
    {                                                                          \
        for (numBusyLoops = 0; numBusyLoops < 10; numBusyLoops++)              \
        {                                                                      \
            PRINT("timeStampTime: %llu\n", timeStampTime[numBusyLoops]);       \
            timeStamp2 += timeStampTime[numBusyLoops];                         \
        }                                                                      \
    }                                                                          \
    do_div(timeStamp2, 10);                                                    \
    PRINT("timestamp2: %llu\n", timeStamp2);                                   \
                                                                               \
    PRINT("busyLoops: %u\n", busyLoopCount);                                   \
    if (busyLoopMethod_g == 2)                                                 \
    {                                                                          \
        timeStampTime_g = timeStampTime_g * (busyLoopCount);                   \
        PRINT("Mid Point Total cycles: %llu \n",                               \
              (setup->performanceStats->midCyclesTimestamp -                   \
               setup->performanceStats->startCyclesTimestamp));                \
        PRINT("BusyLoopCycles %llu\n",                                         \
              setup->performanceStats->totalBusyLoopCycles);                   \
        PRINT("busyLoopCount: %u \n", busyLoopCount);                          \
        setup->performanceStats->offloadCycles =                               \
            (setup->performanceStats->midCyclesTimestamp -                     \
             setup->performanceStats->startCyclesTimestamp) -                  \
            setup->performanceStats->totalBusyLoopCycles - timeStamp2;         \
    }                                                                          \
    else                                                                       \
    {                                                                          \
        busyLoopTimeStamp();                                                   \
                                                                               \
        startBusyLoop = busyLoopTimeStamp();                                   \
        for (numBusyLoops = 0; numBusyLoops < busyLoopCount; numBusyLoops++)   \
        {                                                                      \
            busyLoop(busyLoopValue, &staticAssign);                            \
        }                                                                      \
        endBusyLoop = busyLoopTimeStamp();                                     \
                                                                               \
        setup->performanceStats->totalBusyLoopCycles =                         \
            endBusyLoop - startBusyLoop;                                       \
        PRINT("BusyLoopCycles %llu\n",                                         \
              setup->performanceStats->totalBusyLoopCycles);                   \
        setup->performanceStats->offloadCycles =                               \
            (setup->performanceStats->endCyclesTimestamp -                     \
             setup->performanceStats->startCyclesTimestamp) -                  \
            setup->performanceStats->totalBusyLoopCycles;                      \
    }                                                                          \
    do_div(setup->performanceStats->offloadCycles,                             \
           (setup->performanceStats->responses));                              \
    PRINT("Offload cycles %llu\n", setup->performanceStats->offloadCycles);

/**
 *******************************************************************************
 * Update numLoops and numOperations when enableStopTests is enabled
 * param input  : loops
 * param output : setup, pPerfStats
 ******************************************************************************/
#define StopTestEnabled(loops, setup, pPerfStats)                              \
    do                                                                         \
    {                                                                          \
        if (stopTestsIsEnabled_g)                                              \
        {                                                                      \
            /* Check if terminated by global flag. If yes, update              \
             * numOperations and numLoops */                                   \
            if (CPA_TRUE == exitLoopFlag_g)                                    \
            {                                                                  \
                setup->numLoops = loops + OFFSET_LOOP_EXIT;                    \
                pPerfStats->numOperations =                                    \
                    (Cpa64U)numLoops * setup->numBuffers;                      \
            }                                                                  \
        }                                                                      \
    } while (0)

typedef enum tlspfs_sign_mode_s
{
    TLSPFS_SIGN_MODE_RSA = 0,
    TLSPFS_SIGN_MODE_ECDSA
} tlspfs_sign_mode_t;

/*enum to define Diffie-Hellman phase*/
typedef enum dh_phase_s
{
    DH_PHASE_1 = 0,
    DH_PHASE_2
} dh_phase_t;

/*enum to define ECDSA step*/
typedef enum ecdsa_step_s
{
    ECDSA_STEP_SIGNRS = 0,
    ECDSA_STEP_VERIFY,
    ECDSA_STEP_POINT_MULTIPLY
} ecdsa_step_t;

#ifdef SC_SM2_ENABLED
/*enum to define SM2 step */
typedef enum sm2_step_s
{
    SM2_STEP_SIGN = 0,
    SM2_STEP_VERIFY,
    SM2_STEP_ENC,
    SM2_STEP_DEC,
    SM2_STEP_KEYEX_P1,
    SM2_STEP_KEYEX_P2
} sm2_step_t;
#endif /* SC_SM2_ENABLED */

/*enum to define DSA step*/
typedef enum dsa_step_s
{
    DSA_STEP_SIGNRS = 0,
    DSA_STEP_VERIFY
} dsa_step_t;

#if CY_API_VERSION_AT_LEAST(3, 0)
/*add for SM3 and SM4*/
typedef struct smx_key_size_pairs_s
{
    CpaCySymCipherAlgorithm cipherAlg;
    Cpa32U cipherKeySizeInBytes;
    CpaCySymHashAlgorithm hashAlg;
    Cpa32U hashKeySizeInBytes;
    Cpa32U cipherOffset;

} smx_key_size_pairs_t;

/*enum to define EC-Gen step */
typedef enum ec_gen_step_s
{
    EC_GEN_VERIFY = 0,
    EC_GEN_MULTIPLY
} ec_gen_step_t;
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

#define POLLED (2)
#define DEFAULT_SAMPLE_CODE_SLEEP (2)
#define DEFAULT_POLL_INTERVAL_NSEC (2100)
#define DEFAULT_SLEEP_INTERVAL_NSEC (200)
#define DEFAULT_POLL_INTERVAL_MSEC (2)
#define DEFAULT_POLL_INTERVAL_KERNEL (0)

/*
******************************************************************************
* Symmetric related performance defines
******************************************************************************
*/
#define SHA1_AUTH_KEY_LENGTH_IN_BYTES (160 / NUM_BITS_IN_BYTE)
#define SHA512_AUTH_KEY_LENGTH_IN_BYTES (512 / NUM_BITS_IN_BYTE)
#define HASH_OFFSET_BYTES (0)
#define CIPHER_OFFSET_BYTES (0)
#define KEY_SIZE_32_IN_BYTES (32 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_64_IN_BYTES (64 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_96_IN_BYTES (96 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_128_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_160_IN_BYTES (160 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_192_IN_BYTES (192 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_224_IN_BYTES (224 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_256_IN_BYTES (256 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_384_IN_BYTES (384 / NUM_BITS_IN_BYTE)
#define KEY_SIZE_512_IN_BYTES (512 / NUM_BITS_IN_BYTE)
#define MD5_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define SHA1_DIGEST_LENGTH_IN_BYTES (160 / NUM_BITS_IN_BYTE)
#define SHA224_DIGEST_LENGTH_IN_BYTES (224 / NUM_BITS_IN_BYTE)
#define SHA256_DIGEST_LENGTH_IN_BYTES (256 / NUM_BITS_IN_BYTE)
#define SHA384_DIGEST_LENGTH_IN_BYTES (384 / NUM_BITS_IN_BYTE)
#define SHA512_DIGEST_LENGTH_IN_BYTES (512 / NUM_BITS_IN_BYTE)
#define AES_XCBC_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define AES_CCM_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define AES_CCM_DEFAULT_NONCE_LENGTH (104 / NUM_BITS_IN_BYTE)
#define AES_CCM_MIN_AAD_ALLOC_LENGTH (256 / NUM_BITS_IN_BYTE)
#define AES_GCM_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define KASUMI_F9_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define SNOW3G_UIA2_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define AES_CMAC_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define AES_CBC_MAC_DIGEST_LENGTH_IN_BYTES (128 / NUM_BITS_IN_BYTE)

#define KASUMI_F9_OR_SNOW3G_UIA2_KEY_SIZE_128_IN_BYTES (128 / NUM_BITS_IN_BYTE)
#define KASUMI_F9_DIGEST_RESULT_LENGTH_IN_BYTES (32 / NUM_BITS_IN_BYTE)
#define SNOW3G_UIA2_DIGEST_RESULT_LENGTH_IN_BYTES (32 / NUM_BITS_IN_BYTE)

#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
/*ZUC_EIA3 produces 32bit digest*/
#define ZUC_EIA3_DIGEST_LENGTH_IN_BYTES (32 / NUM_BITS_IN_BYTE)
#define SHA3_DIGEST_256_LENGTH_IN_BYTES (32)
#define SHA3_256_KEYLENGTH_136_IN_BYTES (136)
#endif

#define MD5_BLOCK_LENGTH_IN_BYTES (64)
#define SHA1_BLOCK_LENGTH_IN_BYTES (64)
#define SHA_224_BLOCK_LENGTH_IN_BYTES (64)
#define SHA_256_BLOCK_LENGTH_IN_BYTES (64)
#define SHA_384_BLOCK_LENGTH_IN_BYTES (128)
#define SHA_512_BLOCK_LENGTH_IN_BYTES (128)
#define AES_XCBC_BLOCK_LENGTH_IN_BYTES (16)
#define SNOW3G_UIA2_BLOCK_LENGTH_IN_BYTES (8)
#define ZUC_EIA3_BLOCK_LENGTH_IN_BYTES (4)
#define SHA3_256_BLOCK_LENGTH_IN_BYTES (136)


/*add for SM3 and SM4*/
#define SM3_DIGEST_LENGTH_IN_BYTES (32)

#define BUFFER_SIZE_0 (0)
#define BUFFER_SIZE_32 (32)
#define BUFFER_SIZE_40 (40)
#define BUFFER_SIZE_64 (64)
#define BUFFER_SIZE_128 (128)
#define BUFFER_SIZE_256 (256)
#define BUFFER_SIZE_304 (304)
#define BUFFER_SIZE_320 (320)
#define BUFFER_SIZE_512 (512)
#define BUFFER_SIZE_752 (752)
#define BUFFER_SIZE_768 (768)
#define BUFFER_SIZE_1024 (1024)
#define BUFFER_SIZE_1027 (1027)
#define BUFFER_SIZE_1152 (1152)
#define BUFFER_SIZE_1280 (1280)
#define BUFFER_SIZE_1408 (1408)
#define BUFFER_SIZE_1460 (1460)
#define BUFFER_SIZE_1504 (1504)
#define BUFFER_SIZE_1536 (1536)
#define BUFFER_SIZE_2048 (2048)
#define BUFFER_SIZE_4096 (4096)
#define BUFFER_SIZE_7680 (7680)
#define BUFFER_SIZE_8192 (8192)
#define BUFFER_SIZE_8992 (8992)
#define BUFFER_SIZE_16384 (16384)
#define BUFFER_SIZE_32768 (32768)
#define BUFFER_SIZE_65536 (65536)
#define BUFFER_SIZE_131072 (131072)
#define BUFFER_SIZE_1048576 (1048576)
#define BUFFER_SIZE_10485760 (10485760)
#define BUFFER_SIZE_1073741824 (1073741824)
#define BUFFER_SIZE_2147483648 (2147483648)
#define BUFFER_SIZE_4294967295 (4294967295)

/*define IV len for 8 and 16 byte block ciphers*/
#define IV_LEN_FOR_8_BYTE_BLOCK_CIPHER (8)
#define IV_LEN_FOR_12_BYTE_BLOCK_CIPHER (12)
#define IV_LEN_FOR_16_BYTE_BLOCK_CIPHER (16)
#define IV_LEN_FOR_24_BYTE_BLOCK_CIPHER (24)
#define IV_LEN_FOR_12_BYTE_GCM (12)
#define IV_LEN_FOR_16_BYTE_GCM (16)


#define DIGEST_RESULT_4BYTES (4)

#define THROUGHPUT_MIN_SUBMISSIONS (100000)

#define DP_POLLING_TIMEOUT (200000000)

/******************************************************************************
 * RSA/DSA Test Params
 *****************************************************************************/
#define MODULUS_256_BIT (256)
#define MODULUS_512_BIT (512)
#define MODULUS_768_BIT (768)
#define MODULUS_1024_BIT (1024)
#define MODULUS_1536_BIT (1536)
#define MODULUS_2048_BIT (2048)
#define MODULUS_3072_BIT (3072)
#define MODULUS_4096_BIT (4096)
#define EXPONENT_160_BIT (160)
/*we are testing 180 bit, but the API requires an even number of bytes as an
 * input so we round up to 184 bits*/
#define EXPONENT_180_BIT (184)
#define EXPONENT_224_BIT (224)
#define EXPONENT_256_BIT (256)

/******************************************************************************
 * EC Test Params
 *****************************************************************************/
/*The API requires number of bytes as input, so we round up to the nearest
 * byte in the actual size*/
#define GFP_P192_SIZE_IN_BITS (192)
#define GFP_P192_SIZE_IN_BYTES (24)
#define GFP_P224_SIZE_IN_BITS (224)
#define GFP_P224_SIZE_IN_BYTES (28)
#define GFP_P256_SIZE_IN_BITS (256)
#define GFP_P256_SIZE_IN_BYTES (32)
#define GFP_P384_SIZE_IN_BITS (384)
#define GFP_P384_SIZE_IN_BYTES (48)
#define GFP_P521_SIZE_IN_BITS (521)
#define GFP_P521_SIZE_IN_BYTES (66)
#define GFP_BP512_SIZE_IN_BITS (512)
#define GFP_BP512_SIZE_IN_BYTES (64)
#define GF2_B163_SIZE_IN_BITS (163)
#define GF2_B163_SIZE_IN_BYTES (21)
#define GF2_B233_SIZE_IN_BITS (233)
#define GF2_B233_SIZE_IN_BYTES (30)
#define GF2_B283_SIZE_IN_BITS (283)
#define GF2_B283_SIZE_IN_BYTES (36)
#define GF2_B409_SIZE_IN_BITS (409)
#define GF2_B409_SIZE_IN_BYTES (52)
#define GF2_B571_SIZE_IN_BITS (571)
#define GF2_B571_SIZE_IN_BYTES (72)
#define GF2_K163_SIZE_IN_BITS (163)
#define GF2_K163_SIZE_IN_BYTES (21)
#define GF2_K233_SIZE_IN_BITS (233)
#define GF2_K233_SIZE_IN_BYTES (30)
#define GF2_K283_SIZE_IN_BITS (283)
#define GF2_K283_SIZE_IN_BYTES (36)
#define GF2_K409_SIZE_IN_BITS (409)
#define GF2_K409_SIZE_IN_BYTES (52)
#define GF2_K571_SIZE_IN_BITS (571)
#define GF2_K571_SIZE_IN_BYTES (72)

#ifdef SC_SM2_ENABLED
/******************************************************************************
 * SM2 Test Params
 *****************************************************************************/
#define GFP_SM2_SIZE_IN_BYTE (32)
/*According to the SM2 spec, KDF function will pad a 4-bytes counter to the
 * end of each data block. For a performance reason, the KDF function need
 * more 4-bytes memory pre-malloced for the input data.
 */
#define KDF_COUNTER_PADDING (4)
#define GFP_SM2_COORDINATE_SIZE_IN_BYTE GFP_SM2_SIZE_IN_BYTE
/*encoded point, 1 byte header + 32 bytes x coordinate + 32 bytes y coordinate
 */
#define GFP_SM2_POINT_SIZE_IN_BYTE (2 * GFP_SM2_SIZE_IN_BYTE + 1)
/*this is used for kdf function in SM2 key exchange
 * 32 bytes x coordinate + 32 bytes y coordinate + 4 bytes padding counter
 */
#define SM3_HASH_SIZE_IN_BYTE GFP_SM2_SIZE_IN_BYTE
#define HEADER_UNCOMPRESSION_POINT (0x04)
#define SECRET_KEY_LEN_IN_BYTE (16)
#define GFP_SM2_SIZE_IN_BITS (256)
#endif /* SC_SM2_ENABLED */

#define GFP_NISTP192_BITMASK 0x1
#define GFP_NISTP224_BITMASK 0x2
#define GFP_NISTP256_BITMASK 0x4
#define GFP_NISTP384_BITMASK 0x8
#define GFP_NISTP521_BITMASK 0x10
#define GFP_BP512_BITMASK 0x20
#define GF2_NISTK163_BITMASK 0x40
#define GF2_NISTK233_BITMASK 0x80
#define GF2_NISTK283_BITMASK 0x100
#define GF2_NISTK409_BITMASK 0x200
#define GF2_NISTK571_BITMASK 0x400
#define GF2_NISTB163_BITMASK 0x800
#define GF2_NISTB233_BITMASK 0x1000
#define GF2_NISTB283_BITMASK 0x2000
#define GF2_NISTB409_BITMASK 0x4000
#define GF2_NISTB571_BITMASK 0x8000

/*the following are defined in the framework, these are used for setup only
 * and are not to be used in functions not thread safe*/
extern Cpa8U thread_setup_g[MAX_THREAD_VARIATION]
                           [MAX_SETUP_STRUCT_SIZE_IN_BYTES];
extern Cpa8U thread_name_g[MAX_THREAD_VARIATION][THREAD_NAME_LEN];
extern Cpa32U testTypeCount_g;
extern thread_creation_data_t testSetupData_g[];
extern single_thread_test_data_t singleThreadData_g[];
extern CpaCySymCipherDirection cipherDirection_g;

#define ONE_PACKET (1)

extern Cpa32U numPacketSizes;
extern Cpa32U numWirelessPacketSizes;
extern Cpa32U numModSizes;

extern Cpa32U packetSizes[];
extern Cpa32U wirelessPacketSizes[];
extern Cpa32U modSizes[];


/*define a back off mechanism to stop performance operations constantly using
 * up 100% CPU.*/

CpaStatus setCyPollInterval(Cpa32U interval);
#if defined(KERNEL_SPACE)
/*set a context switch to allow OS re-schedule thread, it also allows other
 *threads CPU time on the same core*/
/*note the soft lockup can be compiled out of the kernel, if that is the case
 * this step is not needed*/
#define AVOID_SOFTLOCKUP                                                       \
    do                                                                         \
    {                                                                          \
        yield();                                                               \
        /*set_current_state(TASK_INTERRUPTIBLE); */                            \
        /*schedule_timeout(0 * HZ); */                                         \
    } while (0)
#define AVOID_SOFTLOCKUP_POLL AVOID_SOFTLOCKUP
#else /* defined(KERNEL_SPACE) */
/* FreeBSD scheduler is not handling "busy loops" as effective as Linux
 * especially in multi-thread environment where few polling threads
 * can be assigned to single CPU core. To avoid thread starvation
 * sched_yields has been replaced by usleep to balance CPU time more
 * equal across polling threads.*/
#define AVOID_SOFTLOCKUP_POLL                                                  \
    do                                                                         \
    {                                                                          \
        if (cyPollingThreadsInterval_g)                                        \
            usleep(cyPollingThreadsInterval_g);                                \
        else                                                                   \
            sched_yield();                                                     \
    } while (0)
#define AVOID_SOFTLOCKUP                                                       \
    do                                                                         \
    {                                                                          \
        sched_yield();                                                         \
    } while (0)
#endif

/*
******************************************************************************
* Byte Alignment settings
******************************************************************************
*/
/*these are used to align memory to a byte boundary*/
#define BYTE_ALIGNMENT_8 (8)
#define BYTE_ALIGNMENT_64 (64)

/*prime number generation defines*/
#define NB_MR_ROUNDS (2)
#define NUM_PRIME_GENERATION_RETRY_ATTEMPTS (1000)
#define NUM_PRIME_GENERATION_ATTEMPTS (100)

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      allocate a CpaFlatBuffer pointer some memory, allocate the pData and
 *      copy in any data if given
 *
 *****************************************************************************/
#define ALLOC_FLAT_BUFF_DATA(instanceHandle,                                   \
                             pFlatBuf,                                         \
                             sizeOfData,                                       \
                             pCopyData,                                        \
                             sizeOfCopyData,                                   \
                             FREE_MEM_FUNC)                                    \
    do                                                                         \
    {                                                                          \
        status = bufferDataMemAlloc(                                           \
            instanceHandle, pFlatBuf, sizeOfData, pCopyData, sizeOfCopyData);  \
        if (CPA_STATUS_SUCCESS != status)                                      \
        {                                                                      \
            PRINT_ERR("Failed to allocate flat buffer memory\n");              \
            FREE_MEM_FUNC;                                                     \
            return CPA_STATUS_FAIL;                                            \
        }                                                                      \
    } while (0)

#define MR_PRIME_MIN_BUFF_LEN (64)

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *      For Miller Rabin Primality Tests. The size of the buffer MUST be
 *
 *      n * (MAX(64,x))
 *
 * where:
 *
 * - n is the requested number of rounds.
 * - x is the minimum number of bytes required to represent the prime
 *   candidate, i.e. x = ceiling((ceiling(log2(p)))/8).
 *
 *   This macro definition performs MAX(64,x)
 *
 *****************************************************************************/
#define MR_PRIME_LEN(x)                                                        \
    do                                                                         \
    {                                                                          \
        if (x < MR_PRIME_MIN_BUFF_LEN)                                         \
        {                                                                      \
            x = MR_PRIME_MIN_BUFF_LEN;                                         \
        }                                                                      \
    } while (0)

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      Symmetric Setup Data.
 * @description
 *      This structure contains data relating to setting up a symmetric test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct symmetric_test_params_s
{
    /*stores the setup data thread running symmetric operations*/
    CpaCySymSessionSetupData setupData;
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /*pointer to an array with NUM_PRE_ALLOCATED_BUFF_LISTS elements, each
     * element of this array stores the CpaFlatBuffer.dataLenInBytes
     *  size, that each CpaBufferList points at. This array is used to support
     *  the IMIX packet variation, otherwise all elements are the same size*/
    Cpa32U *packetSizeInBytesArray;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /*number of buffer lists to be created*/
    Cpa32U numBuffers;
    /*Flag to digestIsAppended*/
    Cpa32U numBuffLists;
    /*number of buffer to be created, only for sym perf load */
    Cpa32U numLoops;
    /*number of Op in one cpaCySymDpEnqueueOpBatch, if numOpDpBatch is 0,
     * system will run cpaCySymDpEnqueueOp, otherwise cpaCySymDpEnqueueOpBatch
     */
    Cpa32U numSessions;
    /* Unique thread ID based on the order in which the thread was created */
    Cpa32U digestAppend;
    /*Flat Buffer Size in Buffer List
     * if flatBufferSizeInBytes is 0, there is one Flat buffer in the list */
    Cpa32U flatBufferSizeInBytes;
    /*number of times numBuffers is looped over performing operations*/
    Cpa32U numOpDpBatch;
    /* number of request will execute at one time.
     * If numRequests is 0, the operation should be performed immediately
     * (performOpNow = CPA_TRUE)
     * otherwise, On every Nth request (e.g. N=16), the operations will be
     * performed. */
    Cpa32U numRequests;
    /*numberOfSession per thread*/
    Cpa32U threadID;
    /* Identify to output of results if calling function is DataPlane API*/
    CpaBoolean isDpApi;
    /*crypto source offset*/
    Cpa32U cryptoSrcOffset;
    CpaBoolean isMultiSGL;
    /* Initial Value Length */
    Cpa32U ivLength;
    /* Digest verify failures */
    Cpa64U initialVerifyFailures;
    Cpa32U submissions;
    Cpa32U node;
    /**< Variable to triger generating of random numbers for nested has inside
     * of setup function to avoid mismatch caused by using shared buffers
     * between threads.
     */
    CpaCySymHashNestedModeSetupData nestedSetupData;
    Cpa8U nestedHashInnerPrefix[SHA512_DIGEST_LENGTH_IN_BYTES];
    Cpa8U nestedHashOuterPrefix[SHA512_DIGEST_LENGTH_IN_BYTES];
    CpaBoolean checkCongestion;
    /* If flat buffer size is not divisible by 1KB then enable the packet round
     * off */
    CpaBoolean enableRoundOffPkt;
    /* Identify if the test is for SSL or TLS*/
    CpaBoolean isTLS;
} symmetric_test_params_t;

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      Asymmetric Setup Data.
 * @description
 *      This structure contains data relating to setting up an asymmetric test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct asym_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /*size of Modulus to test*/
    Cpa32U modulusSizeInBytes;
    /*size of the exponent to test*/
    Cpa32U exponentSizeInBytes;
    /*number of buffers to be created*/
    Cpa32U numBuffers;
    /*number of times numBuffers is looped over performing operations*/
    Cpa32U numLoops;
    /*field to select the DH phase*/
    dh_phase_t phase;
    /*rsa key type*/
    CpaCyRsaPrivateKeyRepType rsaKeyRepType;
    /*rsa operation*/
    CpaBoolean performEncrypt;
    Cpa32U threadID;
    CpaBoolean checkCongestion;
#if CY_API_VERSION_AT_LEAST(3, 0)
    CpaBoolean enableKPT;
    CpaCyKptHandle kptKeyHandle;
#endif
} asym_test_params_t;

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      DSASetup Data.
 * @description
 *      This structure contains data relating to setting up a DSA test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct dsa_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /*key length L and N, FIPS 186-3 specifies L and N bit length pairs of
     * (1024,160), (2048,224), (2048,256), and (3072,256).*/
    Cpa32U pLenInBytes;
    Cpa32U qLenInBytes;
    /*number of buffers to be created*/
    Cpa32U numBuffers;
    /*number of times numBuffers is looped over performing operations*/
    Cpa32U numLoops;
    /* hash algorithm to use in getting the digest of the message being
     * signed by DSA*/
    CpaCySymHashAlgorithm hashAlg;
    Cpa32U threadID;
} dsa_test_params_t;

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      ECDSA Curve structure.
 * @description
 *      This structure is used to store the elliptic curve data
 *
 ****************************************************************************/
typedef struct ec_curves_s
{
    /*size of elliptic curve*/
    Cpa8U nLenInBytes;
    /*type of EC curve*/
    CpaCyEcFieldType fieldType;
    /*pointers to EC curve parameters*/
    Cpa8U *p;
    Cpa32U sizeOfp;
    Cpa8U *r;
    Cpa32U sizeOfr;
    Cpa8U *a;
    Cpa32U sizeOfa;
    Cpa8U *b;
    Cpa32U sizeOfb;
    Cpa8U *xg;
    Cpa32U sizeOfxg;
    Cpa8U *yg;
    Cpa32U sizeOfyg;
} ec_curves_t;

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      ECDSA Setup Data.
 * @description
 *      This structure contains data relating to setting up an ECDSA test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct ecdsa_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;

    Cpa32U nLenInBytes;
    CpaCyEcFieldType fieldType;
    Cpa32U numBuffers;
    Cpa32U numLoops;
    ecdsa_step_t step;
    ec_curves_t *pCurve;
    Cpa32U threadID;
#if CY_API_VERSION_AT_LEAST(3, 0)
    CpaBoolean enableKPT;
    CpaCyKptHandle kptKeyHandle;
#endif
} ecdsa_test_params_t;

#ifdef SC_SM2_ENABLED
/**
 * ******************************************************************************
 * @ingroup cryptoThreads
 *      SM2 Setup Data.
 * @description
 *      This structure contains data relating to setting up an SM2 performance
 *      test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct sm2_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;

    Cpa32U nLenInBytes;
    CpaCyEcFieldType fieldType;
    Cpa32U numBuffers;
    Cpa32U numLoops;
    sm2_step_t step;
    CpaFlatBuffer *digest;
    CpaFlatBuffer *message;
    CpaFlatBuffer *cipher;
    CpaFlatBuffer *random;
    CpaFlatBuffer *d;
    CpaFlatBuffer *d2;
    CpaFlatBuffer *xP;
    CpaFlatBuffer *yP;
    CpaFlatBuffer *x1;
    CpaFlatBuffer *y1;
    CpaFlatBuffer *x2;
    CpaFlatBuffer *y2;
    CpaCyEcsm2VerifyOpData **verifyOp;
} sm2_test_params_t;

/**
 ******************************************************************************
 * @ingroup cryptoThreads
 *      SM2  Temp Data.
 * @description
 *      This structure contains data relating to setting up an SM2 performance
 *      test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct sm2_perf_buf_s
{
    CpaFlatBuffer *pC1Buffer;
    CpaFlatBuffer *pC2Buffer;
    CpaFlatBuffer *pC3Buffer;
    CpaFlatBuffer *pHashBuffer;
    CpaFlatBuffer *pIntermediateBuffer;
    CpaFlatBuffer *pEncOutputData;
    CpaFlatBuffer *pDecOutputData;
    CpaCyEcsm2EncryptOutputData *pEncPKEOut;
    CpaCyEcsm2DecryptOutputData *pDecPKEOut;
    CpaCyEcsm2KeyExOutputData *pKeyexPKEOut;
} sm2_perf_buf_t;

/**
 *******************************************************************************
 * @ingroup cryptoThreads
 *      SM2 Callback Tag.
 * @description
 *      This structure contains data relating to setting up an SM2 performance
 *      test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 *
 *****************************************************************************/
typedef struct sm2_perf_test_s
{
    sm2_test_params_t *setup;
    sm2_perf_buf_t *perf_buffer;
} sm2_perf_test_t;
#endif /* SC_SM2_ENABLED */

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      PLS TFS Setup Data.
 * @description
 *      This structure contains data relating to setting up an PLS TFS test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct tlspfs_test_params_s
{
    asym_test_params_t param;
    Cpa32U nLenInBytes;
    Cpa32U fieldType;
    Cpa32U signOp;
    Cpa32U signSize;
} tlspfs_test_params_t;

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      symSessionUpdateTest
 *
 * @description
 *      setup a test to run a session update test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus sessionUpdateTest(Cpa32U numLoops, Cpa32U numBuffers);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      symSessionUpdateTestDp
 *
 * @description
 *      setup a test to run a session update test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus sessionUpdateTestDp(Cpa32U numLoops, Cpa32U numBuffers);

#if CY_API_VERSION_AT_LEAST(2, 3)
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 * @description
 *      This structure contains data relating to setting up an HKDF test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct hkdf_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /*numberOfSession per thread*/
    Cpa32U threadID;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /* test vector used */
    Cpa32U testVector;
    /* HKDF operation */
    Cpa8U hkdfOp;
    /* HKDF cipherSuite */
    CpaCyKeyHKDFCipherSuite cipherSuite;
    /* number of buffers to be generated */
    Cpa32U numBuffers;
    /* number of loops to be generated */
    Cpa32U numLoops;
} hkdf_test_params_t;

/**
 *****************************************************************************
 * @ingroup ecMontEdwdsThreads
 * @description
 *      This structure contains data relating to setting up an ecMontEdwds test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct ec_montedwds_test_params_s
{
    /* pointer to pre-allocated memory for thread to store performance data */
    perf_data_t *performanceStats;
    /* crypto instance handle of service that has already been started */
    CpaInstanceHandle cyInstanceHandle;
    /* numberOfSession per thread */
    Cpa32U threadID;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /* generator operation used */
    CpaBoolean generator;
    /* field type */
    CpaCyEcMontEdwdsCurveType curveType;
    /* test vector used */
    Cpa32U vector;
    /* number of buffers to be generated */
    Cpa32U numBuffers;
    /* number of loops to be generated */
    Cpa32U numLoops;
} ec_montedwds_test_params_t;
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */

#if CY_API_VERSION_AT_LEAST(3, 0)
/**
 *****************************************************************************
 * @ingroup ecGenericThreads
 * @description
 *      This structure contains data relating to setting up an ecGeneric test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct ec_generic_test_params_s
{
    /* pointer to pre-allocated memory for thread to store performance data */
    perf_data_t *performanceStats;
    /* crypto instance handle of service that has already been started */
    CpaInstanceHandle cyInstanceHandle;
    /* numberOfSession per thread */
    Cpa32U threadID;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /* alignment */
    Cpa32U alignment;
    /* generator operation used */
    CpaBoolean generator;
    /* curve bitmask*/
    Cpa32U curveBitmask;
    /* test vector used - currently not used as only 1 vector defined */
    Cpa32U vector;
    /* number of buffers to be generated */
    Cpa32U numBuffers;
    /* number of loops to be generated */
    Cpa32U numLoops;
    /* EC Gen step */
    ec_gen_step_t step;
} ec_generic_test_params_t;
#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      NRBG Setup Data.
 * @description
 *      This structure contains data relating to setting up an NRBG test.
 *      The client needs to complete the information in this structure in order
 *      to setup a test.
 *
 ****************************************************************************/
typedef struct nrbg_test_params_s
{
    /*pointer to pre-allocated memory for thread to store performance data*/
    perf_data_t *performanceStats;
    /*crypto instance handle of service that has already been started*/
    CpaInstanceHandle cyInstanceHandle;
    /* run test using synchronous or asynchronous mode */
    sync_mode_t syncMode;
    /* number of bytes to be generated */
    Cpa32U nLenInBytes;
    /* number of buffers to be generated */
    Cpa32U numBuffers;
    /* number of loops to be generated */
    Cpa32U numLoops;
} nrbg_test_params_t;

#ifdef SC_SM2_ENABLED
/**
 *******************************************************************************
 *  @ingroup cryptoThreads
 *       setupSm2Test
 *
 *  @description
 *       setup a test to run an sm2 performance test
 *       - should be called before createTheads framework function
 ******************************************************************************/
CpaStatus setupSm2Test(Cpa32U nLenInBits,
                       CpaCyEcFieldType fieldType,
                       sync_mode_t syncMode,
                       sm2_step_t step,
                       Cpa32U numBuffers,
                       Cpa32U numLoops);
#endif /* SC_SM2_ENABLED */

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      Random nested hash Setup Data.
 * @description
 *      This structure contains data to trigger generating of random numbers for
 *      nested hash inside of setup function to avoid mismatch caused by
 *      using shared buffers between
 *
 ****************************************************************************/
typedef struct nested_hash_test_setup_s
{
    /*API nested has structure*/
    CpaCySymHashNestedModeSetupData nestedSetupData;
    /*Flag to generate random values inside setup function */
    CpaBoolean generateRandom;
} nested_hash_test_setup_t;

/* *****************************************************************************
 * FUNCTION PROTOTYPES
 * ****************************************************************************/
void processCallback(void *pCallbackTag);

#define FREE_NUMA_MEM(buf)                                                     \
    do                                                                         \
    {                                                                          \
        /*check that the pointer is not null, for an uninitialized flat buffer \
         * the pData address could be 0x00000001*/                             \
        if (buf != NULL)                                                       \
        {                                                                      \
            qaeMemFreeNUMA((void **)&buf);                                     \
        }                                                                      \
    } while (0)

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      startCyServices
 *
 * @description
 *      This function starts all Crypto services available on the system
 *****************************************************************************/
CpaStatus startCyServices(void);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      stopCyServices
 *
 * @description
 *      This function stops all Crypto services running on the system,
 *      any requests in flight are canceled
 *****************************************************************************/
CpaStatus stopCyServices(void);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      getThroughput
 *
 * @description
 *      get the throughput in Megabits per second
 *      =(numPackets*packetSize)*(cycles/cpu_frequency)
 *****************************************************************************/
Cpa32U getThroughput(Cpa64U numPackets,
                     Cpa32U packetSize,
                     perf_cycles_t cycles);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      getOpsPerSecond
 *
 * @description
 *      This function gets the operations completed per second. One operation is
 *      performed per packet so this is equivalent of packets processed per
 *      second.
 *****************************************************************************/
Cpa32U getOpsPerSecond(Cpa64U responses, perf_cycles_t cycles);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      printAsymStatsAndStopServices
 *
 * @description
 *      This function prints asymmetric crypto performance stats
 *****************************************************************************/
CpaStatus printAsymStatsAndStopServices(thread_creation_data_t *data);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupEcdsaTest
 *
 * @description
 *      setup a test to run an ECDSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupEcdsaTest(Cpa32U nLenInBits,
                         CpaCyEcFieldType fieldType,
                         sync_mode_t syncMode,
                         ecdsa_step_t step,
                         Cpa32U numBuffers,
                         Cpa32U numLoops);
#if CY_API_VERSION_AT_LEAST(3, 0)
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupKpt2EcdsaTest
 *
 * @description
 *      setup a test to run a KPT ECDSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupKpt2EcdsaTest(Cpa32U nLenInBits,
                             CpaCyEcFieldType fieldType,
                             sync_mode_t syncMode,
                             ecdsa_step_t step,
                             Cpa32U numBuffers,
                             Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleECDSACode
 *
 * @description
 * This function frees all memory related to KPT2 data.
 * ****************************************************************************/
void kpt2EcdsaFreeDataMemory(CpaCyKptEcdsaSignRSOpData *pKPTSignRSOpData,
                             CpaCyKptUnwrapContext *pKptUnwrapCtx);
#endif

#if CY_API_VERSION_AT_LEAST(2, 3)
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *
 * @description
 *****************************************************************************/
CpaStatus setupKeyGenHkdfTest(sync_mode_t syncMode,
                              Cpa32U testVector,
                              CpaCyKeyHKDFOp hkdfOp,
                              CpaCyKeyHKDFCipherSuite cipherSuite,
                              Cpa32U numBuffers,
                              Cpa32U numLoops);
/* The API version check does not guarantee if EC Mont Edwards is
 * suported by the driver. This function checks by making an API
 * call to see if the status reports CPA_STATUS_UNSUPPORTED.
 */
CpaBoolean isECMontEdwdsSupported(void);

/**
 *****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 *      setup a test to run an ecMontEdwds test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupEcMontEdwdsTest(sync_mode_t syncMode,
                               CpaBoolean generator,
                               CpaCyEcMontEdwdsCurveType curveType,
                               Cpa32U vector,
                               Cpa32U numBuffers,
                               Cpa32U numLoops);
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */

#if CY_API_VERSION_AT_LEAST(3, 0)
/* The API version check does not guarantee if EC Generic Curves are
 * suported by the driver. This function checks by making an API
 * call to see if the status reports CPA_STATUS_UNSUPPORTED.
 */
CpaBoolean isECGenericCurveSupported(void);

/**
 *****************************************************************************
 * @ingroup ecGenericThreads
 *
 * @description
 *      setup a test to run an ecGeneric test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupEcGenericTest(sync_mode_t syncMode,
                             Cpa32U alignment,
                             CpaBoolean generator,
                             Cpa32U curveSelectedBitmask,
                             Cpa32U vector,
                             Cpa32U numBuffers,
                             Cpa32U numLoops,
                             ec_gen_step_t step);

#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupTlsPfsTest
 *
 * @description
 *      setup a test to run an TLSPFS test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupTlspfsTest(Cpa32U nLenInBits,
                          CpaCyEcFieldType fieldType,
                          Cpa32U signOp,
                          Cpa32U signSize,
                          Cpa32U numBuffers,
                          Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupDsaTest
 *
 * @description
 *      setup a test to run an DSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupDsaTest(Cpa32U pLenInBits,
                       Cpa32U qLenInBits,
                       sync_mode_t syncMode,
                       Cpa32U numBuffers,
                       Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupDsaSignTest
 *
 * @description
 *      setup a test to run an DSA sign only test
 *      - should be called before createTheads framework function
 *****************************************************************************/

CpaStatus setupDsaSignTest(Cpa32U pLenInBits,
                           Cpa32U qLenInBits,
                           sync_mode_t syncMode,
                           Cpa32U numBuffers,
                           Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupRsaTest
 *
 * @description
 *      setup a test to run an RSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupRsaTest(Cpa32U modulusSize,
                       CpaCyRsaPrivateKeyRepType rsaKeyRepType,
                       sync_mode_t syncMode,
                       Cpa32U numBuffs,
                       Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupRsaEncryptTest
 *
 * @description
 *      setup a test to run an RSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupRsaEncryptTest(Cpa32U modulusSize,
                              CpaCyRsaPrivateKeyRepType rsaKeyRepType,
                              sync_mode_t syncMode,
                              Cpa32U numBuffs,
                              Cpa32U numLoops);

#if CY_API_VERSION_AT_LEAST(3, 0)
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupKpt2RsaTest
 *
 * @description
 *      setup a test to run KPT RSA test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupKpt2RsaTest(Cpa32U modulusSize,
                           CpaCyRsaPrivateKeyRepType rsaKeyRepType,
                           sync_mode_t syncMode,
                           Cpa32U numBuffs,
                           Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup sampleKPTRSACode
 *
 * @description
 * This function frees all memory related to KPT2 data.
 * ****************************************************************************/
void kpt2RsaFreeDataMemory(asym_test_params_t *setup,
                           CpaCyKptUnwrapContext **pKptUnwrapCtx,
                           CpaCyKptRsaDecryptOpData **ppKPTDecryptOpData);
#endif

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupDhTest
 *
 * @description
 *      setup a test to run an Diffie Hellman test
 *      - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupDhTest(Cpa32U modSizeInBits,
                      Cpa32U expSizeInBits,
                      sync_mode_t syncMode,
                      dh_phase_t phase,
                      Cpa32U numBuffs,
                      Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupIkeRsaTest
 *
 * @description
 *      setup a test to run an Ike RSA simulation test
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupIkeRsaTest(Cpa32U modSizeInBits,
                          Cpa32U expSizeInBits,
                          Cpa32U numBuffs,
                          Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleSymmetricTest
 *
 * @description
 * setup a symmetric test
 * This function needs to be called from main to setup a symmetric test.
 * then the framework createThreads function is used to propagate this setup
 * across cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupSymmetricTest(CpaCySymOp opType,
                             CpaCySymCipherAlgorithm cipherAlg,
                             Cpa32U cipherKeyLengthInBytes,
                             Cpa32U cipherOffset,
                             CpaCyPriority priority,
                             CpaCySymHashAlgorithm hashAlg,
                             CpaCySymHashMode hashMode,
                             Cpa32U authKeyLengthInBytes,
                             CpaCySymAlgChainOrder chainOrder,
                             sync_mode_t syncMode,
                             nested_hash_test_setup_t *nestedModeSetupDataPtr,
                             Cpa32U packetSize,
                             Cpa32U bufferSizeInBytes,
                             Cpa32U numBuffLists,
                             Cpa32U numLoops,
                             Cpa32U digestAppend);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupCipherTest
 *
 * @description
 *      This is the setup function for performing cipher performance tests
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupCipherTest(CpaCySymCipherAlgorithm cipherAlg,
                          Cpa32U cipherKeyLengthInBytes,
                          CpaCyPriority priority,
                          sync_mode_t useAsync,
                          Cpa32U packetSize,
                          Cpa32U bufferSizeInBytes,
                          Cpa32U numBufferLists,
                          Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupHashTest
 *
 * @description
 *      This is the setup function for performing hash performance tests
 *      should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupHashTest(CpaCySymHashAlgorithm hashAlg,
                        CpaCySymHashMode hashMode,
                        /*used to setup hash and hmac test,
                        authKeyLenInBytes is 0 for plain hash operation*/
                        Cpa32U authKeyLengthInBytes,
                        CpaCyPriority priority,
                        sync_mode_t useAsync,
                        Cpa32U packetSize,
                        Cpa32U numBufferLists,
                        Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupAlgChainTest
 *
 * @description
 *      This is the setup function for performing symmetric algorithm chaining
 *      performance tests
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupAlgChainTest(CpaCySymCipherAlgorithm cipherAlg,
                            Cpa32U cipherKeyLengthInBytes,
                            CpaCySymHashAlgorithm hashAlg,
                            CpaCySymHashMode hashMode,
                            Cpa32U authKeyLengthInBytes,
                            CpaCySymAlgChainOrder chainOrder,
                            CpaCyPriority priority,
                            sync_mode_t useAsync,
                            Cpa32U packetSize,
                            Cpa32U bufferSizeInBytes,
                            Cpa32U numBufferLists,
                            Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup an IPsec scenario where payload = IP packet, the IP header is not
 * encrypted thus requires an offset into the buffer to test.
 *
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 ******************************************************************************/
CpaStatus setupIpSecTest(CpaCySymCipherAlgorithm cipherAlg,
                         Cpa32U cipherKeyLengthInBytes,
                         Cpa32U cipherOffset,
                         CpaCySymHashAlgorithm hashAlg,
                         CpaCySymHashMode hashMode,
                         Cpa32U authKeyLengthInBytes,
                         CpaCySymAlgChainOrder chainOrder,
                         Cpa32U packetSize,
                         Cpa32U numBufferLists,
                         Cpa32U numLoops);
/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test with hash in nested mode, setting the data for nested
 * hash.
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 *******************************************************************************/
CpaStatus setupAlgChainTestNestedMode(
    CpaCySymCipherAlgorithm cipherAlg,
    Cpa32U cipherKeyLengthInBytes,
    CpaCySymHashAlgorithm hashAlg,
    Cpa32U authKeyLengthInBytes,
    CpaCySymAlgChainOrder chainOrder,
    CpaCyPriority priority,
    sync_mode_t syncMode,
    nested_hash_test_setup_t *nestedModeSetupData,
    Cpa32U packetSize,
    Cpa32U numBufferLists,
    Cpa32U numLoops);
/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test with High Priority
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 *******************************************************************************/
CpaStatus setupAlgChainTestHP(CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              CpaCySymAlgChainOrder chainOrder,
                              sync_mode_t syncMode,
                              Cpa32U packetSize,
                              Cpa32U numBufferLists,
                              Cpa32U numLoops);

/******************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * setup a alg chain test with Normal Priority
 * This function needs to be called from main to setup an alg chain test.
 * then the framework createThreads function is used to propagate this setup
 * across IA cores using different crypto logical instances
 *******************************************************************************/
CpaStatus setupAlgChainTestNP(CpaCySymCipherAlgorithm cipherAlg,
                              Cpa32U cipherKeyLengthInBytes,
                              CpaCySymHashAlgorithm hashAlg,
                              CpaCySymHashMode hashMode,
                              Cpa32U authKeyLengthInBytes,
                              CpaCySymAlgChainOrder chainOrder,
                              sync_mode_t syncMode,
                              Cpa32U packetSize,
                              Cpa32U numBufferLists,
                              Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupAlgChainTestHPAsync
 *
 * @description
 *      This is the setup function for performing symmetric algorithm chaining
 *      performance tests fixing High priority and async mode
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupAlgChainTestHPAsync(CpaCySymCipherAlgorithm cipherAlg,
                                   Cpa32U cipherKeyLengthInBytes,
                                   CpaCySymHashAlgorithm hashAlg,
                                   CpaCySymHashMode hashMode,
                                   Cpa32U authKeyLengthInBytes,
                                   CpaCySymAlgChainOrder chainOrder,
                                   Cpa32U packetSize,
                                   Cpa32U numBufferLists,
                                   Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupSessionUpdateCipher
 *
 * @description
 *      This is the setup function for performing cipher performance tests
 *      with session update
 *       - should be called before createTheads framework function
 */
CpaStatus setupSessionUpdateCipher(CpaCySymCipherAlgorithm cipherAlgorithm,
                                   Cpa32U cipherKeyLen,
                                   CpaCyPriority priority,
                                   sync_mode_t syncMode,
                                   Cpa32U packetSize,
                                   Cpa32U numOfPacketsInBuffer,
                                   Cpa32U numBuffers,
                                   Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupCipherUpdateHash
 *
 * @description
 *      This is the setup function for performing hash performance tests
 *      with session update
 *       - should be called before createTheads framework function
 */
CpaStatus setupSessionUpdateHash(CpaCySymHashAlgorithm hashAlgorithm,
                                 Cpa32U authKeyLen,
                                 CpaCySymHashMode hashMode,
                                 Cpa32U digestResultLenInBytes,
                                 CpaCyPriority priority,
                                 sync_mode_t syncMode,
                                 Cpa32U packetSize,
                                 Cpa32U numOfPacketsInBuffer,
                                 Cpa32U numBuffers,
                                 Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupSessionUpdateAlgChain
 *
 * @description
 *      This is the setup function for performing symmetric algorithm chaining
 *      performance tests with session update
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupSessionUpdateAlgChain(CpaCySymCipherAlgorithm cipherAlgorithm,
                                     Cpa32U cipherKeyLen,
                                     CpaCySymHashAlgorithm hashAlgorithm,
                                     Cpa32U authKeyLen,
                                     CpaCySymHashMode hashMode,
                                     Cpa32U digestResultLenInBytes,
                                     CpaCySymAlgChainOrder chainOrder,
                                     CpaCyPriority priority,
                                     sync_mode_t syncMode,
                                     Cpa32U packetSize,
                                     Cpa32U numOfPacketsInBuffer,
                                     Cpa32U numBuffers,
                                     Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupSessionUpdateCipherDp
 *
 * @description
 *      This is the setup function for performing cipher performance tests
 *      with session update
 *       - should be called before createTheads framework function
 */
CpaStatus setupSessionUpdateCipherDp(CpaCySymCipherAlgorithm cipherAlgorithm,
                                     Cpa32U cipherKeyLen,
                                     CpaCyPriority priority,
                                     sync_mode_t syncMode,
                                     Cpa32U packetSize,
                                     Cpa32U numOfPacketsInBuffer,
                                     Cpa32U numBuffers,
                                     Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupCipherUpdateHashDp
 *
 * @description
 *      This is the setup function for performing hash performance tests
 *      with session update
 *       - should be called before createTheads framework function
 */
CpaStatus setupSessionUpdateHashDp(CpaCySymHashAlgorithm hashAlgorithm,
                                   Cpa32U authKeyLen,
                                   CpaCySymHashMode hashMode,
                                   Cpa32U digestResultLenInBytes,
                                   CpaCyPriority priority,
                                   sync_mode_t syncMode,
                                   Cpa32U packetSize,
                                   Cpa32U numOfPacketsInBuffer,
                                   Cpa32U numBuffers,
                                   Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setupSessionUpdateAlgChainDp
 *
 * @description
 *      This is the setup function for performing symmetric algorithm chaining
 *      performance tests with session update
 *       - should be called before createTheads framework function
 *****************************************************************************/
CpaStatus setupSessionUpdateAlgChainDp(CpaCySymCipherAlgorithm cipherAlgorithm,
                                       Cpa32U cipherKeyLen,
                                       CpaCySymHashAlgorithm hashAlgorithm,
                                       Cpa32U authKeyLen,
                                       CpaCySymHashMode hashMode,
                                       Cpa32U digestResultLenInBytes,
                                       CpaCySymAlgChainOrder chainOrder,
                                       CpaCyPriority priority,
                                       sync_mode_t syncMode,
                                       Cpa32U packetSize,
                                       Cpa32U numOfPacketsInBuffer,
                                       Cpa32U numBuffers,
                                       Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleSymmetricPerformance
 *
 * @description
 *      This function is the thread launched by the framework
 *      It sets up the arrayOfBuffer sizes to test, copies data
 *       from the single_thread_test_data_t to the symmetric_test_params
 *       structure and calls the sampleSymmetricPerform function
 *****************************************************************************/
void sampleSymmetricPerformance(single_thread_test_data_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleSymmetricPerform
 *
 * @description
 *      This is a thread context function that does the Symmetric session
 *      initialization and perform operations
 *****************************************************************************/
CpaStatus sampleSymmetricPerform(symmetric_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleCreateBuffers
 *
 * @description
 *      Sets an array of bufferLists and flatBuffers and populates them with
 *      random data
 *****************************************************************************/
CpaStatus sampleCreateBuffers(CpaInstanceHandle instanceHandle,
                              Cpa32U packetSizeInBytes[],
                              CpaFlatBuffer *pFlatBuffArray[],
                              CpaBufferList *pBuffListArray[],
                              symmetric_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleFreeBuffers
 *
 * @description
 *      This function frees the memory allocated for the array of buffer
 *        lists and flat buffers.
 *****************************************************************************/
void sampleFreeBuffers(CpaFlatBuffer *srcBuffPtrArray[],
                       CpaBufferList *srcBuffListArray[],
                       symmetric_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dpSampleCreateBuffers
 *
 * @description
 *      Sets an array of physical bufferLists and physical flatBuffers and
 *      populates them with random data
 *****************************************************************************/
CpaStatus dpSampleCreateBuffers(CpaInstanceHandle instanceHandle,
                                Cpa32U packetSizeInBytesArray[],
                                CpaBufferList *pBuffListArray[],
                                CpaPhysBufferList *pPhyBuffListArray[],
                                symmetric_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dpSampleFreeBuffers
 *
 * @description
 *      This function frees the memory allocated for the array of physical
 *      bufferlists and physical flat buffers.
 *****************************************************************************/
void dpSampleFreeBuffers(CpaBufferList *srcBuffListArray[],
                         CpaPhysBufferList *srcPhyBuffListArray[],
                         Cpa32U numBuffLists,
                         Cpa32U numBuffers);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleRsaPerform
 *
 * @description
 *      This is a thread context function that performs the RSA operations
 *****************************************************************************/
CpaStatus sampleRsaPerform(asym_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      symPerformCallback
 *
 * @description
 *      This functions handles a symmetric crypto request callback
 *
 *****************************************************************************/
void symPerformCallback(void *pCallbackTag,
                        CpaStatus status,
                        const CpaCySymOp operationType,
                        void *pOpData,
                        CpaBufferList *pDstBuffer,
                        CpaBoolean verifyResult);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaDecryptCallback
 *
 * @description
 *      This function handles the requested RSA operations callback
 *
 *****************************************************************************/
void rsaDecryptCallback(void *pCallbackTag,
                        CpaStatus status,
                        void *pOpdata,
                        CpaFlatBuffer *pOut);

#if CY_API_VERSION_AT_LEAST(2, 3)
/*****************************************************************************
 * @ingroup hkdfThreads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * HKDF operation has been processed
 *****************************************************************************/
void hkdfCallback(void *pCallbackTag,
                  CpaStatus status,
                  void *pOpData,
                  CpaFlatBuffer *pOut);

/*****************************************************************************
 * @ingroup ecMontEdwdsThreads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * ecMontEdwds operation has been processed
 *****************************************************************************/
void ecMontEdwdsCallback(void *pCallbackTag,
                         CpaStatus status,
                         void *pOpData,
                         CpaBoolean multiplyStatus,
                         CpaFlatBuffer *pXk,
                         CpaFlatBuffer *pYk);
#endif /* CY_API_VERSION_AT_LEAST(2, 3) */

#if CY_API_VERSION_AT_LEAST(3, 0)
/*****************************************************************************
 * @ingroup ecGenericThreads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * ecGenericVerify operation has been processed
 *****************************************************************************/
void ecGenericVerifyCallback(void *pCallbackTag,
                             CpaStatus status,
                             void *pOpData,
                             CpaBoolean verifyStatus);

/*****************************************************************************
 * @ingroup ecGenericThreads
 *
 * @description
 * Asymmetric callback function: This function is invoked when a
 * ecGenericMultiply operation has been processed
 *****************************************************************************/
void ecGenericMultiplyCallback(void *pCallbackTag,
                               CpaStatus status,
                               void *pOpData,
                               CpaBoolean multiplyStatus,
                               CpaFlatBuffer *pXk,
                               CpaFlatBuffer *pYk);

#endif /* CY_API_VERSION_AT_LEAST(3, 0) */

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      printSymmetricPerfDataAndStopCyService
 *
 * @description
 *      This function prints out symmetric crypto performance stats
 *
 *****************************************************************************/
CpaStatus printSymmetricPerfDataAndStopCyService(thread_creation_data_t *data);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      printRsaPerfData
 *
 * @description
 *      This function prints out RSA CRT performance stats
 *
 *****************************************************************************/
CpaStatus printRsaCrtPerfData(thread_creation_data_t *data);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      printRsaPerfData
 *
 * @description
 *      This function prints out RSA performance stats
 *
 *****************************************************************************/
CpaStatus printRsaPerfData(thread_creation_data_t *data);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      getNumCyclesPerOp
 *
 * @description
 *      This function gets the number of cycles taken to process a packet
 *
 *****************************************************************************/
perf_cycles_t getNumCyclesPerOp(perf_cycles_t numOfCycles,
                                Cpa32U numOperations);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setCpaFlatBufferMSB
 *
 * @description
 *      This function ensures that the MSB (pData[0]) is set (ie 0x80)
 *
 *****************************************************************************/
void setCpaFlatBufferMSB(CpaFlatBuffer *buf);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      makeParam1SmallerThanParam2
 *
 * @description
 *      This function takes two pointers to data of equal length and ensures
 *      that param1 is smaller than param2, by subtracting from param1 until
 *      it is smaller than param2. The user needs to ensure that the data
 *      pointed for param1 and param2 is of equal length
 *
 *****************************************************************************/
void makeParam1SmallerThanParam2(Cpa8U *param1,
                                 Cpa8U *param2,
                                 Cpa32U len,
                                 CpaBoolean msbSettingRequired);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      conformMillerRabinData
 *
 * @description
 *      As there's a limit on the minimum buffer size used to contain the Miller
 *      Rabin Data(MAX(64,required_buffer_size)), we still must satisfy the
 *      conditions that Miller Rabin data is >1 and less than Prime -1.
 *      If the Miller Rabin buffer length is greater than the smallest Prime
 *      Candidate buffer length, we need to zero the most significant bytes of
 *      the difference and ensure that the actual data length is the same.
 *
 *****************************************************************************/
void conformMillerRabinData(CpaFlatBuffer *pMR,
                            CpaFlatBuffer *pSmallestPC,
                            Cpa32U rounds);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      generatePrime
 *
 * @description
 *      This function generates a prime number of a length as given in the
 *      input CpaFlatBuffer
 *
 *****************************************************************************/
CpaStatus generatePrime(CpaFlatBuffer *primeCandidate,
                        CpaInstanceHandle cyInstanceHandle,
                        asym_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      generateHardCodedPrime1P
 *
 * @description
 *      This function generates a hardcoded prime number of a length as given
 *      in the input CpaFlatBuffer
 *
 *****************************************************************************/
CpaStatus generateHardCodedPrime1P(CpaFlatBuffer *primeCandidate,
                                   asym_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      generateHardCodedPrime2Q
 *
 * @description
 *      This function generates a hardcoded prime number of a length as given
 *      in the input CpaFlatBuffer
 *
 *****************************************************************************/
CpaStatus generateHardCodedPrime2Q(CpaFlatBuffer *primeCandidate,
                                   asym_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      freeArrayFlatBufferNUMA
 *
 * @description
 *      This function frees the pData, the pointers and array of pointers of
 *      a multi dimensional CpaFlatBuffer array
 *
 *****************************************************************************/
void freeArrayFlatBufferNUMA(CpaFlatBuffer *buf, Cpa32U numBuffs);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      setHashDigestLen
 *
 * @description
 *      This function sets a hash digest length  based on the passed in hash
 *      algorithm
 *
 *****************************************************************************/
Cpa32U setHashDigestLen(CpaCySymHashAlgorithm hashAlgorithm);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      getHashPartialPacketSize
 *
 * @description
 *      This function gets hash partial packet size based on the input algorithm
 *      and packet size
 *
 *****************************************************************************/
Cpa32U getHashPartialPacketSize(CpaCySymHashAlgorithm hashAlgorithm,
                                Cpa32U packetSize);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      calcDigest
 *
 * @description
 *      This function calculates the digest of a given message
 *
 *****************************************************************************/
CpaStatus calcDigest(CpaInstanceHandle instanceHandle,
                     CpaFlatBuffer *msg,
                     CpaFlatBuffer *digest,
                     CpaCySymHashAlgorithm hashAlg);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      calcSWDigest
 *
 * @description
 *      This function use IA(SW) to calculate the digest of a given message
 *
 *****************************************************************************/

CpaStatus calcSWDigest(CpaFlatBuffer *msg,
                       CpaFlatBuffer *digest,
                       CpaCySymHashAlgorithm hashAlg);

CpaStatus getCyInstanceCapabilities(CpaCyCapabilitiesInfo *pCap);

CpaStatus getCySpecificInstanceCapabilities(CpaInstanceHandle instanceHandle,
                                            CpaCyCapabilitiesInfo *pCap);
CpaStatus getCryptoInstanceCapabilities(CpaCyCapabilitiesInfo *cap,
                                        Cpa32U instType);

#if CY_API_VERSION_AT_LEAST(3, 0)
CpaStatus getSymAsymInstanceCapabilities(CpaCyCapabilitiesInfo *pCap,
                                         Cpa32U instType);
#endif
CpaStatus getCySymQueryCapabilities(CpaCySymCapabilitiesInfo *pCap);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      removeSymSession
 *
 * @description
 *      This function removes symmetric session (in ASYNC mode it waits for
 *      pending callbacks to finish).
 *
 *****************************************************************************/
CpaStatus removeSymSession(CpaInstanceHandle instanceHandle,
                           CpaCySymSessionCtx pSessionCtx);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      bufferDataMemAlloc
 *
 * @description
 *      This function allocates physically contiguous pData memory to a
 *      CpaFlatBuffer
 *
 *****************************************************************************/
CpaStatus bufferDataMemAlloc(CpaInstanceHandle instanceHandle,
                             CpaFlatBuffer *buf,
                             Cpa32U size,
                             Cpa8U *copyData,
                             Cpa32U sizeOfCopyData);


/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      generateRSAKey
 *
 * @description
 *      This function generates RSA public and private keys
 *
 *****************************************************************************/
CpaStatus generateRSAKey(CpaInstanceHandle instanceHandle,
                         Cpa32U modulusLenInBytes,
                         CpaCyRsaPrivateKey *pPrivateKey,
                         CpaCyRsaPublicKey *pPublicKey,
                         asym_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleCodeCyGetNode
 *
 * @description
 *      This function gets the node affinity of a crypto instance
 *
 *****************************************************************************/
CpaStatus sampleCodeCyGetNode(CpaInstanceHandle instanceHandle, Cpa32U *node);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhCallback
 *
 * @description
 *      This function processes Diffie Hellman responses
 *
 *****************************************************************************/
void dhCallback(void *pCallbackTag,
                CpaStatus status,
                void *pOpData,
                CpaFlatBuffer *pOut);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhPhase1Setup
 *
 * @description
 *      This function sets up Diffie Hellman Phase1 data
 *
 *****************************************************************************/
CpaStatus dhPhase1Setup(asym_test_params_t *setup,
                        CpaCyDhPhase1KeyGenOpData **pAlicePhase1,
                        CpaCyDhPhase1KeyGenOpData **pBobPhase1,
                        CpaFlatBuffer **pAlicePublicValue,
                        CpaFlatBuffer **pBobPublicValue,
                        CpaCyRsaPublicKey **pKey);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhPhase1
 *
 * @description
 *      This function  performs Diffie Hellman Phase1 operations
 *
 *****************************************************************************/
CpaStatus dhPhase1(CpaCyDhPhase1KeyGenOpData **pCpaDhOpDataP1,
                   CpaFlatBuffer **pLocalOctetStringPV,
                   asym_test_params_t *setup,
                   Cpa32U numBuffers,
                   Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhPhase2Setup
 *
 * @description
 *      This function sets up Diffie Hellman Phase2 data
 *
 *****************************************************************************/
CpaStatus dhPhase2Setup(CpaFlatBuffer *pSecretKey[],
                        CpaCyDhPhase1KeyGenOpData *pCpaDhOpDataP1[],
                        CpaCyDhPhase2SecretKeyGenOpData *pCpaDhOpDataP2[],
                        CpaFlatBuffer *pLocalOctetStringPV[],
                        asym_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhPhase2
 *
 * @description
 *      This function  performs Diffie Hellman Phase2 operations
 *
 *****************************************************************************/
CpaStatus dhPhase2Perform(CpaFlatBuffer **pOctetStringSecretKey,
                          CpaCyDhPhase2SecretKeyGenOpData **pCpaDhOpDataP2,
                          asym_test_params_t *setup,
                          Cpa32U numBuffers,
                          Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhMemFreePh1
 *
 * @description
 *      This function frees Diffie Hellman Phase1 data
 *
 *****************************************************************************/
void dhMemFreePh1(asym_test_params_t *setup,
                  CpaCyDhPhase1KeyGenOpData **pAlicePhase1,
                  CpaFlatBuffer **pAlicePublicValue,
                  CpaCyDhPhase1KeyGenOpData **pBobPhase1,
                  CpaFlatBuffer **pBobPublicValue);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      dhMemFreePh2
 *
 * @description
 *      This function frees Diffie Hellman Phase2 data
 *
 *****************************************************************************/
void dhMemFreePh2(asym_test_params_t *setup,
                  CpaFlatBuffer **pAliceSecretKey,
                  CpaCyDhPhase2SecretKeyGenOpData **pAlicePhase2,
                  CpaFlatBuffer **pBobSecretKey,
                  CpaCyDhPhase2SecretKeyGenOpData **pBobPhase2);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaEncryptDataSetup
 *
 * @description
 *      This function sets RSA encrypt operation data
 *
 *****************************************************************************/
CpaStatus rsaEncryptDataSetup(CpaFlatBuffer *pEncryptData[],
                              CpaCyRsaEncryptOpData *pOpdata[],
                              CpaFlatBuffer *pOutputData[],
                              asym_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaDecryptDataSetup
 *
 * @description
 *      This function sets RSA decrypt operation data
 *
 *****************************************************************************/
CpaStatus rsaDecryptDataSetup(CpaFlatBuffer *pDecryptData[],
                              CpaCyRsaDecryptOpData *pOpdata[],
                              CpaFlatBuffer *pOutputData[],
                              asym_test_params_t *setup);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      genKeyArray
 *
 * @description
 *      This function generates RSA keys
 *
 *****************************************************************************/
CpaStatus genKeyArray(asym_test_params_t *setup,
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[]);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaSetOpDataKeys
 *
 * @description
 *      This copies RSA keys into the encrypt and decrypt operation data
 *      structures
 *
 *****************************************************************************/
void rsaSetOpDataKeys(asym_test_params_t *setup,
                      CpaCyRsaDecryptOpData *pDecryptOpData[],
                      CpaCyRsaEncryptOpData *pEncryptOpData[],
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[]);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaFreeDataMemory
 *
 * @description
 *      This function frees RSA encrypt and decrypt data memory
 *
 *****************************************************************************/
void rsaFreeDataMemory(asym_test_params_t *setup,
                       CpaCyRsaDecryptOpData *pOpdata[],
                       CpaFlatBuffer *pOutputData[],
                       CpaCyRsaEncryptOpData *pEncryptOpdata[],
                       CpaFlatBuffer *pInputData[]);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      rsaFreeKeyMemory
 *
 * @description
 *      This function frees RSA key memory
 *
 *****************************************************************************/
void rsaFreeKeyMemory(asym_test_params_t *setup,
                      CpaCyRsaPrivateKey *pPrivateKey[],
                      CpaCyRsaPublicKey *pPublicKey[]);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleRsaEncrypt
 *
 * @description
 *      This function performs RSA encryption operations
 *
 *****************************************************************************/
CpaStatus sampleRsaEncrypt(asym_test_params_t *setup,
                           CpaCyRsaEncryptOpData **pEncryptOpData,
                           CpaFlatBuffer **pOutputData,
                           Cpa32U numBuffers,
                           Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      sampleRsaDecrypt
 *
 * @description
 *      This function performs RSA decryption operations
 *
 *****************************************************************************/
CpaStatus sampleRsaDecrypt(asym_test_params_t *setup,
                           CpaCyRsaDecryptOpData **pDecryptOpData,
                           CpaFlatBuffer **pOutputData,
                           CpaCyRsaPrivateKey **pPrivateKey,
                           CpaCyRsaPublicKey **pPublicKey,
                           Cpa32U numBuffers,
                           Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      allocArrayOfPointers
 *
 * @description
 *      This function allocates memory to an array of pointers to structures
 *
 *****************************************************************************/
CpaStatus allocArrayOfPointers(CpaInstanceHandle instanceHandle,
                               void **buf,
                               Cpa32U numBuffs);

CpaStatus allocArrayOfVirtPointers(void **buf, Cpa32U numBuffs);
/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      cyAllocAndSetupInstances
 *
 * @description
 *      This function allocates memory for crypto instances
 *
 *****************************************************************************/
CpaStatus cyAllocAndSetupInstances(void);


/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      waitForResponses
 *
 * @description
 *      This function waits for all response submitted by crypto threads
 *
 *****************************************************************************/
CpaStatus waitForResponses(perf_data_t *perfData,
                           sync_mode_t syncMode,
                           Cpa32U numBuffers,
                           Cpa32U numLoops);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      cyCreatePollingThreadsIfPollingIsEnabled
 *
 * @description
 *      This function checks whether each instance handle is set for polling
 *      and will allocate create and start the same number polling threads
 *      as they are polling instances.
 * @pre numInstances_g is set and all instances have been started.
 * @post numPolledInstances_g is set by the function to the number of polling
 *         instances available.
 *
 *****************************************************************************/
CpaStatus cyCreatePollingThreadsIfPollingIsEnabled(void);

/**
 *****************************************************************************
 * @ingroup cryptoThreads
 *      cyCheckAllInstancesArePolled
 *
 * @description
 *      This function checks whether all CY instances are configured for polling
 *      mode, it is used to support the Data Plane API where interrupt mode is
 *      not supported
 * @pre numInstances_g is set and all instances have been started.
 *
 * @retval CPA_TRUE         All instances are configured for polling
 * @retval CPA_FALSE        At least one instance is configured for interrupt
 *                          mode or cannot inspect the CpaInstanceInfo2
 *                          structure.
 *
 *****************************************************************************/
CpaBoolean cyCheckAllInstancesArePolled(void);

/**
 * *****************************************************************************
 *  @ingroup compressionThreads
 *  cyDpPollRemainingOperations
 *
 *  @description
 *      Poll for remaining operations, this function will timeout after
 *      SAMPLE_CODE_WAIT_DEFAULT have elapsed.
 *
 *  @threadSafe
 *      Yes
 *
 *  @param[in] perfData         pointer to performance structure
 *  @param[in] instanceHandle   API CpaInstanceHandle
 *
 *  @retval CPA_STATUS_SUCCESS  No operations to poll for or all remaining
 *                              operations have been polled.
 *  @retval CPA_STATUS_FAIL     Failure from polling operation or timeout.
 ******************************************************************************/
CpaStatus cyDpPollRemainingOperations(perf_data_t *pPerfData,
                                      CpaInstanceHandle instanceHandle);
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * function to print out hash performance header
 ******************************************************************************/
void printHashAlg(CpaCySymHashSetupData hashSetupData);
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *  function to print out cipher performance header
 ******************************************************************************/
void printCipherAlg(CpaCySymCipherSetupData cipherSetupData);
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * print out performance test type
 ******************************************************************************/
void printSymTestType(symmetric_test_params_t *setup);
/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * print out performance data from a collection of threads that
 * were all running the same setup
 ******************************************************************************/
CpaStatus printSymmetricPerfDataAndStopCyService(thread_creation_data_t *data);


CpaStatus cyPollNumOperations(perf_data_t *pPerfData,
                              CpaInstanceHandle instanceHandle,
                              Cpa64U numOperations);

CpaStatus cyPollNumOperationsTimeout(perf_data_t *pPerfData,
                                     CpaInstanceHandle instanceHandle,
                                     Cpa64U numOperations,
                                     Cpa64U timeout);

/*switch the direction of the symmetric performance module*/
CpaStatus switchCipherDirection(void);

/************************************************************************
 * Name: checkCapability
 * Description: Checks whether the given logical instance supports
 *  cipherAlg/hashAlg
 * Return : True if supported, False, otherwise
 ************************************************************************/
CpaBoolean checkCapability(CpaInstanceHandle *cyInstanceHandle,
                           symmetric_test_params_t *symTestSetup);

/**
 *****************************************************************************
 * @ingroup sampleRSACode
 * sampleCodeAsymPollInstance
 *
 * @description
 *      Wrapper function to crypto specific polling function which polls
 *      an asymmetric instance.
 *
 ******************************************************************************/
CpaStatus sampleCodeAsymPollInstance(CpaInstanceHandle instanceHandle,
                                     Cpa32U response_quota);
/**
 *****************************************************************************
 * @ingroup sampleSymmetricCode
 * sampleCodeSymPollInstance
 *
 * @description
 *      Wrapper function to crypto specific polling function which polls
 *      a symmetric instance.
 *
 ******************************************************************************/
CpaStatus sampleCodeSymPollInstance(CpaInstanceHandle instanceHandle,
                                    Cpa32U response_quota);
/**
 ********************************************************************************
 * @ingroup sampleCryptoCode
 * stopCyServices
 *
 * @description
 *     this API stops the Crypto services.
 * @threadSafe
 *     No
 * @param[in] data  pointer to test data structure
 ********************************************************************************/
CpaStatus stopCyServicesFromCallback(thread_creation_data_t *data);
#endif /*_CRYPTO_UTILS_H_*/

/**
 *****************************************************************************
 * @ingroup checkForChachapolySupport
 *
 * @description
 * helper function to check for the instances that support
 * CPA_CY_SYM_CIPHER_CHACHA
 ******************************************************************************/
CpaStatus checkForChachapolySupport(void);
