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
 * @file cpa_sample_code_crypto_utils.c
 *
 * @ingroup cryptoThreads
 *
 * @description
 *      This file contains utility functions for performance sample code
 *
 *****************************************************************************/

#include "cpa_sample_code_crypto_utils.h"
#include "cpa_sample_code_framework.h"
#include "cpa_cy_common.h"
#include "cpa_cy_prime.h"
#include "icp_sal_poll.h"

#define POLL_AND_SLEEP 1

#include "qat_perf_cycles.h"
#include "qat_perf_buffer_utils.h"

#ifdef USER_SPACE
Cpa32U poll_type_g = 0;
Cpa32U sleep_time_g = 0;
#else
Cpa32U poll_type_g = POLL_AND_SLEEP;
Cpa32U sleep_time_g = DEFAULT_POLL_INTERVAL_MSEC;
#endif

CpaBoolean usePartial_g = CPA_FALSE;
unsigned long long timeStampTime_g = 0;
Cpa32U busyLoopMethod_g = 2;
CpaBoolean timeStampInLoop = CPA_FALSE;
EXPORT_SYMBOL(timeStampTime_g);
long cyPollingThreadsInterval_g = 0;
EXPORT_SYMBOL(cyPollingThreadsInterval_g);

#define NUM_BITS_IN_MEGABIT (1000000)
#define LOWEST_EVEN_NUMBER (2)
#define KILOBITS_IN_MEGABITS (1000)
#define MILLI_SECONDS_IN_SECOND (1000)
#define SECOND_LAST_BYTE (2)
#define INC_BY_TWO (2)
#define RESPONSE_NOT_CHECKED (-1)
#define SINGLE_SOCKET (1)
#define NUM_TLS_BUFFERS (2)
#define TLS_HEADER_BUFFERSIZE (13)

CpaBoolean running_dsa_g = CPA_FALSE;

/*flag to indicate whether a thread has started the crypto acceleration service
 */
volatile CpaBoolean cy_service_started_g = CPA_FALSE;
volatile CpaBoolean cy_polling_started_g = CPA_FALSE;
CpaCySymCipherDirection cipherDirection_g = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

volatile CpaBoolean digestAppended_g = CPA_FALSE;
CpaInstanceHandle *cyInstances_g = NULL;
Cpa16U numInstances_g = 0;
Cpa16U numPolledInstances_g = 0;
CpaBoolean allocateMemOnOppositeNode = CPA_FALSE;
extern Cpa32U packageIdCount_g;

Cpa32U packetSizes[] = {BUFFER_SIZE_64,
                        BUFFER_SIZE_128,
                        BUFFER_SIZE_256,
                        BUFFER_SIZE_512,
                        BUFFER_SIZE_1024,
                        BUFFER_SIZE_2048,
                        BUFFER_SIZE_4096,
                        PACKET_IMIX};

Cpa32U numPacketSizes = sizeof(packetSizes) / sizeof(Cpa32U);
EXPORT_SYMBOL(packetSizes);
EXPORT_SYMBOL(numPacketSizes);

Cpa32U wirelessPacketSizes[] = {BUFFER_SIZE_40,
                                BUFFER_SIZE_64,
                                BUFFER_SIZE_256,
                                BUFFER_SIZE_320,
                                BUFFER_SIZE_512,
                                BUFFER_SIZE_1024};

Cpa32U numWirelessPacketSizes = sizeof(wirelessPacketSizes) / sizeof(Cpa32U);
EXPORT_SYMBOL(wirelessPacketSizes);
EXPORT_SYMBOL(numWirelessPacketSizes);

Cpa32U modSizes[] = {
    MODULUS_2048_BIT,
    MODULUS_4096_BIT,
};

Cpa32U numModSizes = sizeof(modSizes) / sizeof(Cpa32U);
EXPORT_SYMBOL(modSizes);
EXPORT_SYMBOL(numModSizes);

extern int signOfLife;
extern int verboseOutput;

sample_code_thread_t *pollingThread_g;

/*
 * DH prime numbers
 */
/* Prime numbers for different types of modulus */

static const Cpa8U m_768[] = {
    0xC7, 0x3B, 0x18, 0xB5, 0x71, 0xE1, 0xE0, 0x7C, 0x70, 0x66, 0x5F, 0xD8,
    0x8B, 0xD9, 0xC2, 0x55, 0x3E, 0xD7, 0x09, 0x68, 0x80, 0xF2, 0x17, 0x1A,
    0x7A, 0x6D, 0xC9, 0x24, 0xF2, 0x5C, 0x84, 0x7D, 0xB4, 0xC5, 0xA5, 0x40,
    0x9A, 0x3F, 0xB7, 0xBD, 0xD4, 0xD0, 0xE6, 0xA0, 0x01, 0xC5, 0x1E, 0xA7,
    0x60, 0x42, 0x2D, 0xF5, 0x16, 0xAF, 0x01, 0x6C, 0xF7, 0xA5, 0x73, 0xCF,
    0x36, 0xB3, 0x6E, 0x5C, 0xE7, 0x2C, 0x18, 0x19, 0x5C, 0x21, 0x40, 0x1B,
    0xF4, 0xD5, 0xD9, 0xF4, 0x46, 0x08, 0xDA, 0x84, 0x0B, 0x34, 0x8F, 0x80,
    0xB9, 0x7C, 0x7B, 0xAF, 0x23, 0xEA, 0x6E, 0xF2, 0x45, 0x8C, 0xC0, 0x0B};

static const Cpa8U m_1024[] = {
    0xED, 0x39, 0xD7, 0x6B, 0xD0, 0x77, 0x37, 0xFB, 0x5A, 0xC1, 0x98, 0x41,
    0x29, 0x58, 0xC4, 0x3E, 0xD9, 0x6A, 0x0B, 0x7C, 0x48, 0xB4, 0x59, 0x69,
    0x54, 0x8F, 0x59, 0x83, 0xE0, 0x73, 0x31, 0x10, 0xA3, 0x6D, 0x5F, 0x51,
    0xDA, 0xD9, 0x8D, 0xC9, 0x09, 0xD1, 0xAF, 0x93, 0xC8, 0xA4, 0x93, 0xEC,
    0xF5, 0x9B, 0x3D, 0x51, 0x7F, 0x72, 0x2C, 0xFB, 0x4D, 0x72, 0x62, 0x8C,
    0xA0, 0x08, 0x9D, 0xE7, 0x40, 0x67, 0x35, 0x7A, 0xB6, 0x99, 0xA7, 0x20,
    0x25, 0x59, 0x04, 0x35, 0x54, 0xC1, 0x78, 0x97, 0x35, 0x8E, 0xF8, 0xF2,
    0x02, 0xB2, 0x6D, 0xF3, 0xA6, 0x1B, 0xBD, 0x0F, 0xE0, 0x38, 0x99, 0x6E,
    0xE0, 0x1D, 0x12, 0x4A, 0x1A, 0xC5, 0x02, 0xF8, 0x74, 0x70, 0x1B, 0x73,
    0xC6, 0x52, 0x59, 0x35, 0xCF, 0xBC, 0xA9, 0x51, 0xCE, 0x87, 0xCE, 0xF1,
    0x21, 0xF8, 0xB8, 0xEE, 0xF0, 0x2D, 0x84, 0xF1};

static const Cpa8U m_1536[] = {
    0xF2, 0x4E, 0x75, 0x1F, 0x5F, 0x61, 0x93, 0x97, 0xBA, 0x9A, 0x5F, 0x3D,
    0xF0, 0x8A, 0xF6, 0x42, 0x14, 0x26, 0x09, 0xE1, 0xFE, 0xFC, 0xC4, 0xAB,
    0x7B, 0x69, 0xFD, 0x68, 0x5D, 0xD7, 0x4C, 0x7F, 0xCB, 0x36, 0xA9, 0x9A,
    0x4D, 0xD8, 0x82, 0x3B, 0xCA, 0x77, 0xE0, 0x93, 0x27, 0xC5, 0x04, 0x60,
    0x08, 0x60, 0x15, 0x40, 0xDF, 0x11, 0x2D, 0x40, 0x83, 0x48, 0x39, 0x46,
    0x81, 0xEC, 0xA1, 0x45, 0xEA, 0x5A, 0x32, 0xE8, 0x15, 0x07, 0x59, 0x03,
    0x42, 0x97, 0xCB, 0xBA, 0x0E, 0xBA, 0x9A, 0xE0, 0xF9, 0x9A, 0xA4, 0x96,
    0x71, 0x62, 0x3B, 0x4D, 0xB0, 0x59, 0xFF, 0x47, 0xB5, 0x06, 0x66, 0xE7,
    0x81, 0xFD, 0x1C, 0x20, 0x84, 0xF5, 0x32, 0x8D, 0xE9, 0x64, 0x32, 0xA0,
    0xAD, 0x3E, 0xB2, 0xD0, 0xAB, 0xC9, 0x2B, 0x24, 0x36, 0x0C, 0x03, 0xB2,
    0x95, 0x07, 0x3F, 0x97, 0x3D, 0x68, 0x05, 0x4E, 0xEE, 0xDB, 0x93, 0x58,
    0x88, 0x81, 0x95, 0x6B, 0x4B, 0x52, 0x62, 0xE2, 0x4D, 0x9C, 0x1C, 0xFB,
    0x0D, 0x47, 0x1B, 0xDB, 0x57, 0x3C, 0x72, 0x73, 0x71, 0x5C, 0xC3, 0x87,
    0x12, 0x81, 0xE0, 0xF1, 0x70, 0x22, 0x08, 0xC2, 0x7B, 0xB0, 0x32, 0x9E,
    0x30, 0x30, 0x7C, 0x86, 0x42, 0xA5, 0xB6, 0x6C, 0xAE, 0xBB, 0xD7, 0x0A,
    0x69, 0x03, 0x02, 0x61, 0xEA, 0xEA, 0x72, 0x08, 0x63, 0xF9, 0x75, 0x99};

static const Cpa8U m_2048[] = {
    0xE9, 0x24, 0x8E, 0x32, 0x0F, 0x73, 0xD2, 0x3E, 0xB4, 0x07, 0x57, 0xA0,
    0xFC, 0xA4, 0xD6, 0xD9, 0xE4, 0xDF, 0xD1, 0xD9, 0x0D, 0x1D, 0xDA, 0x56,
    0xC9, 0x53, 0x74, 0x2F, 0xC4, 0x82, 0x13, 0xFF, 0xF7, 0xF3, 0x47, 0x34,
    0x70, 0x1E, 0x7D, 0x78, 0x1E, 0x38, 0x84, 0x7A, 0xDA, 0xD0, 0xDF, 0x67,
    0x6F, 0xCC, 0x26, 0x6C, 0x64, 0x96, 0x19, 0x71, 0x72, 0x0F, 0x6B, 0x28,
    0x1C, 0xAB, 0x95, 0xBB, 0x2F, 0xA0, 0x13, 0x51, 0x8F, 0x47, 0x5C, 0x42,
    0xF3, 0xC3, 0xFA, 0x46, 0xEF, 0xFC, 0x0F, 0x4C, 0x8D, 0x01, 0x1D, 0xD5,
    0x3B, 0xBF, 0x70, 0xCE, 0x83, 0xD0, 0x79, 0xB3, 0xDE, 0x84, 0xD7, 0xE0,
    0x80, 0xDC, 0x44, 0x36, 0x07, 0x93, 0x50, 0x0A, 0x2F, 0x66, 0xA9, 0xD8,
    0x62, 0x30, 0xB1, 0xD4, 0x6B, 0xD1, 0x86, 0x81, 0x8B, 0x03, 0xE9, 0x72,
    0x12, 0xD2, 0xB9, 0xE0, 0x35, 0x99, 0x22, 0xF9, 0x17, 0x29, 0x1E, 0x8C,
    0x0A, 0x1E, 0x2B, 0xCA, 0xC0, 0xE6, 0x0B, 0x6F, 0x76, 0xD7, 0x91, 0xE0,
    0xD0, 0x0E, 0x6B, 0x6E, 0x10, 0xB8, 0x33, 0xB3, 0xA5, 0xB3, 0xB1, 0x4B,
    0xF6, 0x3D, 0x5F, 0xE0, 0x21, 0xF6, 0x67, 0x96, 0xDA, 0x8F, 0x27, 0xA0,
    0x46, 0x7B, 0xF2, 0xB4, 0x38, 0x05, 0x3C, 0x63, 0xD7, 0xD4, 0xDB, 0x24,
    0x4E, 0xA4, 0x74, 0xF9, 0x00, 0xA2, 0x70, 0x5D, 0x9D, 0x7A, 0x13, 0x19,
    0xF5, 0x98, 0x8A, 0x74, 0xB7, 0x84, 0xA4, 0xD3, 0xB0, 0x5F, 0x61, 0xFD,
    0x90, 0xD3, 0x59, 0xDB, 0x71, 0xF8, 0x57, 0xBD, 0xDF, 0x40, 0xDC, 0x71,
    0x1B, 0xFD, 0x53, 0x7A, 0x0B, 0x76, 0x23, 0xBE, 0x86, 0x46, 0xEB, 0x6B,
    0x2C, 0xEE, 0x17, 0x3D, 0x4F, 0x89, 0xCA, 0xB4, 0x2A, 0x4D, 0x8B, 0x1D,
    0x82, 0x3C, 0xAC, 0x33, 0x53, 0x87, 0x71, 0xB3, 0x45, 0x2A, 0x1C, 0xDD,
    0xB9, 0x78, 0xBF, 0x5B};

static const Cpa8U m_3072[] = {
    0xA2, 0x5F, 0xE5, 0x92, 0xE6, 0x19, 0x98, 0x9B, 0xC5, 0x37, 0xDF, 0x84,
    0x83, 0x5C, 0xED, 0xEE, 0xD1, 0x0E, 0x47, 0xDB, 0x51, 0x15, 0x2E, 0x93,
    0xD1, 0x19, 0x8B, 0xDF, 0x40, 0x91, 0x6D, 0x16, 0x34, 0xB3, 0xDB, 0x7B,
    0xB3, 0x66, 0x6C, 0xAF, 0x0C, 0x5A, 0xCE, 0xF7, 0xB3, 0x57, 0xBE, 0x5F,
    0x76, 0x1D, 0x3C, 0xD4, 0xCC, 0x11, 0x9B, 0xF4, 0x47, 0xB1, 0xCD, 0x11,
    0x65, 0xCF, 0x26, 0x4A, 0x1D, 0xC5, 0x81, 0x51, 0xD4, 0x91, 0x5F, 0xD5,
    0x31, 0x10, 0x8B, 0x83, 0xC5, 0x5A, 0x76, 0xA4, 0x87, 0x08, 0xB2, 0x43,
    0xE1, 0x97, 0xFA, 0x06, 0x89, 0x3D, 0xC5, 0x9B, 0x61, 0x68, 0x60, 0xC5,
    0x21, 0xC6, 0x47, 0xD0, 0x5E, 0xE6, 0xC5, 0xDF, 0x93, 0xE8, 0x7C, 0x63,
    0xB7, 0x81, 0x38, 0x47, 0x45, 0xF2, 0x2E, 0x9A, 0xC2, 0x1E, 0xE1, 0x6F,
    0xE2, 0xAD, 0xE8, 0x3A, 0xAD, 0x44, 0xF7, 0x9B, 0x3A, 0x44, 0x8B, 0x4C,
    0x19, 0xED, 0x3B, 0xF9, 0x83, 0x84, 0x65, 0x21, 0x28, 0xBB, 0x03, 0x8F,
    0x5C, 0x45, 0xFA, 0x44, 0x04, 0x14, 0x0B, 0x76, 0xAA, 0xE4, 0x71, 0x3E,
    0xB1, 0x89, 0x9F, 0x31, 0x43, 0x41, 0x24, 0x59, 0xE1, 0x41, 0x8C, 0x75,
    0x5B, 0x2B, 0xDF, 0x45, 0x44, 0x93, 0x24, 0x7B, 0xA1, 0x33, 0xFE, 0x6E,
    0x76, 0xE9, 0x69, 0xEC, 0xB6, 0x90, 0x3F, 0x93, 0xD2, 0xC4, 0x70, 0x2B,
    0x26, 0x72, 0xB6, 0xCF, 0xC9, 0x11, 0x90, 0xEC, 0x22, 0x45, 0x97, 0x9C,
    0xEB, 0xA9, 0x82, 0x1A, 0xFD, 0x1E, 0xFC, 0x71, 0xCA, 0x6B, 0x3E, 0x33,
    0x9E, 0x4E, 0x9E, 0xC2, 0x18, 0x20, 0xBF, 0x1A, 0xC2, 0x13, 0x24, 0x28,
    0x7E, 0x3E, 0xFC, 0xD7, 0xEE, 0xB4, 0xD3, 0xC1, 0x82, 0xEF, 0x2B, 0x31,
    0xAF, 0xB9, 0xB0, 0xCA, 0xE7, 0x33, 0x93, 0xF6, 0xB7, 0xB2, 0x77, 0x0F,
    0x7A, 0xB1, 0x32, 0xE9, 0xD7, 0x62, 0x03, 0xA1, 0xCE, 0xBF, 0xF6, 0xAB,
    0x77, 0x61, 0x21, 0x9A, 0x92, 0x91, 0x35, 0x50, 0x15, 0x73, 0x32, 0x3D,
    0x80, 0xB7, 0x40, 0xAE, 0xBC, 0x8A, 0xD3, 0x98, 0x65, 0x90, 0x63, 0x25,
    0x39, 0xB2, 0x36, 0xD0, 0xED, 0xC7, 0x02, 0x43, 0x1B, 0xE8, 0x82, 0x40,
    0xBD, 0x6D, 0x33, 0x03, 0x69, 0x46, 0xFB, 0x5D, 0xC5, 0x59, 0xD5, 0x50,
    0xA9, 0x32, 0x2D, 0xC8, 0x11, 0x09, 0x26, 0x0A, 0x2C, 0x82, 0xD8, 0xBF,
    0x39, 0x2B, 0x85, 0xDF, 0x3A, 0x7A, 0xE8, 0xB5, 0x5E, 0xB5, 0x05, 0xA1,
    0xD0, 0xAD, 0x5C, 0x17, 0xE0, 0xC3, 0xA5, 0x34, 0x29, 0x7E, 0x93, 0x2B,
    0xF4, 0x7A, 0x1A, 0x51, 0x71, 0xA6, 0x22, 0x32, 0x47, 0x62, 0xE4, 0x23,
    0x4E, 0xEC, 0xF0, 0x80, 0x17, 0x10, 0x69, 0x6F, 0xD7, 0x8A, 0x5C, 0x7D,
    0xFF, 0x8F, 0x47, 0xCA, 0xB4, 0x1F, 0x27, 0x97, 0xBD, 0x3A, 0x8E, 0x4D};

static const Cpa8U m_4096[] = {
    0xF5, 0x98, 0xBF, 0x63, 0x4A, 0xBD, 0xA9, 0x9A, 0x32, 0x45, 0x9E, 0x36,
    0x2D, 0xC3, 0x1A, 0xE8, 0x62, 0xEB, 0x0F, 0xCC, 0x9E, 0x9D, 0x41, 0xE5,
    0x8F, 0xEA, 0x13, 0x3F, 0xA0, 0xF5, 0xC4, 0xE1, 0xD0, 0xE4, 0x8A, 0xF8,
    0x5C, 0x88, 0x64, 0xD0, 0xDA, 0x60, 0x84, 0x77, 0x5B, 0x02, 0xAD, 0x81,
    0xA1, 0xEC, 0x55, 0xDD, 0xF2, 0x07, 0x45, 0x17, 0x3C, 0xE5, 0xA1, 0xA1,
    0x87, 0x5B, 0xED, 0xBA, 0x20, 0xB8, 0x8D, 0x41, 0x64, 0xBD, 0x53, 0x22,
    0x9A, 0x8B, 0x5D, 0xC3, 0x19, 0x75, 0x3D, 0x3A, 0xAC, 0xF2, 0x7F, 0xBF,
    0x97, 0x88, 0x82, 0x6A, 0x6D, 0xC0, 0x9D, 0xFB, 0x0C, 0x88, 0xC5, 0x03,
    0xE2, 0x2A, 0x4F, 0x21, 0x3A, 0x54, 0xAD, 0x51, 0xC9, 0x3A, 0x32, 0x57,
    0xE1, 0x55, 0x3E, 0x25, 0x84, 0xD2, 0x95, 0xCD, 0x7D, 0x40, 0xC4, 0x99,
    0x3F, 0x2C, 0xE5, 0xBF, 0x04, 0x85, 0xDB, 0xEC, 0xA4, 0xFD, 0x53, 0x6C,
    0x8F, 0x44, 0x89, 0x47, 0x35, 0xDA, 0x7F, 0xCC, 0x22, 0x24, 0x2C, 0xBA,
    0xDF, 0xC3, 0x45, 0x84, 0x1B, 0x9F, 0x9B, 0xD8, 0x8D, 0x9C, 0xC5, 0x36,
    0x2C, 0x46, 0xA0, 0xA0, 0x11, 0x71, 0xE9, 0xA5, 0x9E, 0xFE, 0x63, 0xFB,
    0xA6, 0x6E, 0x08, 0x2A, 0xF9, 0x1A, 0xF9, 0xF0, 0x95, 0x48, 0x13, 0x67,
    0x32, 0x9D, 0xB3, 0xE0, 0xDB, 0xDE, 0xEA, 0x17, 0x69, 0x24, 0x2D, 0xA6,
    0xE0, 0x5A, 0xCC, 0x71, 0xC6, 0x08, 0x9C, 0xAB, 0x12, 0xB7, 0x1A, 0xCC,
    0xEF, 0xE2, 0x1C, 0xB8, 0xD4, 0x37, 0x3A, 0xF8, 0xF3, 0x43, 0x10, 0x41,
    0x45, 0xAB, 0x65, 0x5A, 0x8E, 0xAB, 0xE0, 0x40, 0xF3, 0xD7, 0x07, 0xDF,
    0x5D, 0x9A, 0x4C, 0xB4, 0x37, 0x37, 0x8F, 0x8B, 0xA1, 0xC2, 0x11, 0x14,
    0xF3, 0xD6, 0x5F, 0xA2, 0x8D, 0xD8, 0x8E, 0xE5, 0x76, 0x6D, 0xFE, 0x27,
    0x55, 0x12, 0xCE, 0xAC, 0x03, 0xE0, 0xF7, 0x89, 0xB0, 0xB2, 0xA5, 0xBE,
    0x08, 0x5E, 0xB6, 0x76, 0xC2, 0x2C, 0xD5, 0xBE, 0xDC, 0xE8, 0x51, 0x6D,
    0x9D, 0x93, 0x9F, 0xF2, 0xB5, 0x49, 0xBE, 0xED, 0xB1, 0x1D, 0xDD, 0x09,
    0x2F, 0xA9, 0x66, 0x91, 0x35, 0x8F, 0xB9, 0x60, 0xC4, 0x06, 0x15, 0x28,
    0xDC, 0xD7, 0x42, 0x49, 0x5C, 0x94, 0xFE, 0x17, 0xF4, 0xDC, 0x44, 0xBC,
    0xC6, 0xC4, 0x05, 0x47, 0xB1, 0x44, 0xA4, 0xAC, 0xAF, 0x9E, 0x34, 0xB8,
    0x2A, 0x7C, 0x22, 0xCA, 0x89, 0xF1, 0x98, 0x64, 0xDB, 0x08, 0x7F, 0x4C,
    0xE0, 0xF3, 0xC1, 0x83, 0x70, 0x25, 0x7B, 0xDD, 0x73, 0x6E, 0x55, 0x72,
    0xFE, 0xC2, 0x37, 0xE1, 0x8F, 0x15, 0xD5, 0xB1, 0x1A, 0x59, 0x4F, 0x30,
    0xDA, 0xE8, 0xD2, 0x68, 0x7B, 0x9B, 0xFB, 0x4D, 0xBC, 0xB5, 0x43, 0xEE,
    0x71, 0xAD, 0xBF, 0x2D, 0x91, 0x62, 0x2B, 0xB8, 0x03, 0x5A, 0xBC, 0x94,
    0x65, 0xEA, 0x04, 0xBB, 0x52, 0x96, 0xF4, 0x8C, 0x51, 0xD0, 0xCC, 0xDB,
    0xB0, 0x7D, 0x65, 0x62, 0x1E, 0x74, 0x3D, 0x5D, 0xBA, 0x66, 0x78, 0xAC,
    0xCE, 0xBB, 0xE1, 0x94, 0x63, 0xBE, 0x6C, 0x5F, 0xDF, 0xF3, 0xCD, 0xAC,
    0x34, 0xB3, 0xDB, 0xAF, 0x73, 0x0A, 0x7B, 0x86, 0xFB, 0xC0, 0xE3, 0x56,
    0xEA, 0xDF, 0x84, 0x24, 0xB9, 0x11, 0x8C, 0x98, 0x95, 0xEB, 0x91, 0x25,
    0x7B, 0x44, 0x0C, 0x43, 0xEC, 0xB3, 0x45, 0xBC, 0xA5, 0x37, 0x1F, 0x6E,
    0x8A, 0x4A, 0xD8, 0xA4, 0xD3, 0x64, 0x69, 0x25, 0xD5, 0x3A, 0x4A, 0x7D,
    0xC6, 0x28, 0xB8, 0x55, 0xD3, 0xD4, 0x46, 0x61, 0x83, 0x2D, 0xDD, 0xC4,
    0x53, 0xC3, 0x14, 0xE1, 0x3E, 0x4B, 0xA6, 0x81, 0x37, 0xDE, 0x6A, 0xA5,
    0x4F, 0x33, 0xAC, 0xFD, 0x46, 0xCA, 0x16, 0x00, 0xDA, 0x82, 0xDD, 0xD7,
    0xE7, 0xE1, 0x39, 0xDF, 0x96, 0x77, 0x58, 0xE5};

/*
 * RSA prime numbers
 */
/*
 * 512 Bit Modulus
 */
/* RSA first prime */
static const Cpa8U p_512[] = {0xE7, 0x6C, 0xB1, 0x5B, 0x38, 0xF4, 0x4D, 0x43,
                              0x5F, 0x2A, 0xEC, 0x28, 0xF9, 0xEA, 0x8B, 0xF4,
                              0xB4, 0x52, 0xA8, 0x15, 0x61, 0x01, 0x88, 0x82,
                              0x83, 0x3A, 0xF7, 0x9D, 0x0C, 0xEE, 0x6D, 0xE7};

/* RSA second prime */
static const Cpa8U q_512[] = {0xEA, 0xB1, 0x5B, 0xA0, 0xB1, 0x68, 0x06, 0xD3,
                              0x2E, 0xCD, 0x21, 0xD3, 0x5D, 0x18, 0x91, 0x0B,
                              0x57, 0xC9, 0x03, 0x24, 0x6A, 0xC2, 0x4D, 0xB3,
                              0xFF, 0xAE, 0xE7, 0xEB, 0xF0, 0x91, 0x45, 0xE7};

/*
 * 1024 Bit Modulus
 */
/* RSA first prime */
static const Cpa8U p_1024[] = {
    0xb7, 0x9f, 0x2c, 0x24, 0x93, 0xb4, 0xb7, 0x6f, 0x32, 0x99, 0x03,
    0xd7, 0x55, 0x5b, 0x7f, 0x5f, 0x06, 0xaa, 0xa5, 0xea, 0xab, 0x26,
    0x2d, 0xa1, 0xdc, 0xda, 0x81, 0x94, 0x72, 0x06, 0x72, 0xa4, 0xe0,
    0x22, 0x29, 0xa0, 0xc7, 0x31, 0x50, 0xae, 0x25, 0x65, 0x56, 0xb6,
    0xe6, 0xa4, 0x38, 0xa9, 0x9d, 0x55, 0xaf, 0x7a, 0xa1, 0x59, 0x45,
    0xb9, 0x92, 0xc7, 0xbf, 0x41, 0x61, 0x89, 0xc7, 0x41};

/* RSA second prime */
static const Cpa8U q_1024[] = {
    0xc8, 0x38, 0x7f, 0xd3, 0x8f, 0xa3, 0x3d, 0xdc, 0xea, 0x6a, 0x9d,
    0xe1, 0xb2, 0xd5, 0x54, 0x10, 0x66, 0x35, 0x02, 0xdb, 0xc2, 0x25,
    0x65, 0x5a, 0x93, 0x10, 0xcc, 0xea, 0xc9, 0xf4, 0xcf, 0x1b, 0xce,
    0x65, 0x3e, 0xc9, 0x16, 0xd7, 0x94, 0x07, 0x7c, 0x28, 0x6a, 0xd4,
    0x8c, 0x57, 0xbd, 0x26, 0xa9, 0x65, 0xbf, 0x75, 0x96, 0xb0, 0x48,
    0xfd, 0x51, 0xd6, 0xa4, 0x17, 0x15, 0xe1, 0xb5, 0x17};

/* ***************************************************************/
/* 1536 Bit Modulus*/
/* ***************************************************************/
/* RSA first prime */
static const Cpa8U p_1536[] = {
    0xd5, 0xd2, 0xb2, 0x2a, 0x6d, 0x45, 0x6f, 0x62, 0xa4, 0x17, 0x94, 0x2d,
    0x77, 0xa8, 0x75, 0x9d, 0x04, 0x4d, 0x6f, 0x38, 0xee, 0xf2, 0xa1, 0x7a,
    0x23, 0xd6, 0x95, 0x4c, 0xfd, 0x5a, 0x42, 0x0c, 0x34, 0x11, 0x37, 0xf5,
    0x24, 0x8c, 0x48, 0x82, 0xc6, 0xa0, 0xd0, 0xc7, 0xef, 0xe3, 0xbd, 0x93,
    0xf1, 0x0c, 0xc1, 0x3b, 0x59, 0x12, 0xe6, 0xd3, 0x1b, 0xb4, 0x58, 0x6a,
    0x18, 0x1b, 0x7f, 0x05, 0x93, 0xc5, 0x96, 0x5f, 0x11, 0xbd, 0xcb, 0x40,
    0xd3, 0x97, 0x67, 0xc6, 0x98, 0xfe, 0x3c, 0x84, 0x30, 0x68, 0xfd, 0xe0,
    0xaf, 0x83, 0x13, 0x2f, 0x47, 0x24, 0xd9, 0xe0, 0x46, 0xb6, 0x86, 0x33};

/* RSA second prime */
static const Cpa8U q_1536[] = {
    0xd5, 0xd2, 0xaf, 0x44, 0xdf, 0x74, 0xdd, 0x31, 0xea, 0x0a, 0x36, 0x5c,
    0xb2, 0x3f, 0xa4, 0x1b, 0x60, 0x02, 0x7c, 0x5f, 0x3d, 0x7c, 0x7f, 0xe8,
    0xe5, 0xd3, 0x7d, 0x6a, 0x25, 0x40, 0x37, 0x63, 0xbc, 0xd3, 0xc1, 0xaa,
    0x6e, 0x58, 0x61, 0x69, 0x40, 0x82, 0xca, 0xcb, 0x76, 0x11, 0xd5, 0x52,
    0xfd, 0xf7, 0x1d, 0xd8, 0xef, 0x18, 0x58, 0x8c, 0x50, 0x8d, 0xb6, 0x81,
    0x30, 0x09, 0xce, 0xf6, 0x59, 0xaa, 0x72, 0x19, 0x9f, 0xc1, 0xc9, 0x30,
    0xfa, 0x70, 0xf3, 0xa9, 0x42, 0x08, 0x92, 0x45, 0x53, 0x82, 0x5b, 0xea,
    0xc8, 0x62, 0xc7, 0x43, 0xd8, 0x7d, 0xea, 0x36, 0x01, 0x50, 0x71, 0xb3};

/* ***************************************************************/
/* 2048 Bit Modulus */
/* ***************************************************************/
/* RSA first prime */
static const Cpa8U p_2048[] = {
    0xDF, 0x4D, 0x4D, 0x9A, 0xF6, 0xA4, 0xBC, 0x55, 0xBD, 0xFC, 0x52, 0x03,
    0xB6, 0x5F, 0x1D, 0x1B, 0xFF, 0xD2, 0xCB, 0xD5, 0xE5, 0x9C, 0x44, 0x7D,
    0xBF, 0x3C, 0x23, 0xB1, 0x9B, 0x18, 0x85, 0x25, 0xBA, 0x90, 0xB8, 0x37,
    0x89, 0x2A, 0xDF, 0x23, 0xD5, 0xD5, 0x23, 0xFD, 0x2A, 0xC7, 0x66, 0x98,
    0xB6, 0xBC, 0xAC, 0xF0, 0x1A, 0xC5, 0x4D, 0x6E, 0x90, 0xC7, 0x74, 0x87,
    0xCF, 0x50, 0xA4, 0xAD, 0xD6, 0x52, 0xAF, 0xB4, 0x10, 0x53, 0xEA, 0x21,
    0xA5, 0xF5, 0xCC, 0x0A, 0x4B, 0x34, 0xD0, 0x49, 0x90, 0x62, 0x5F, 0xF7,
    0x65, 0x52, 0xB1, 0x3C, 0x6A, 0x44, 0xD3, 0x1E, 0x72, 0x7D, 0x35, 0x72,
    0x3B, 0xEA, 0xC4, 0x27, 0xE1, 0x35, 0x6C, 0x28, 0x73, 0xD6, 0x0A, 0x05,
    0xA4, 0x8D, 0x06, 0xB2, 0x8E, 0xFE, 0xFF, 0x8E, 0x0D, 0x52, 0xB3, 0x72,
    0x5E, 0xF0, 0x25, 0xA7, 0x42, 0x81, 0x05, 0x6D};

/* RSA second prime */
static const Cpa8U q_2048[] = {
    0xDF, 0x4D, 0x1F, 0xD1, 0x93, 0x6D, 0xFD, 0xF3, 0x61, 0x77, 0x11, 0x08,
    0x58, 0x81, 0x05, 0x21, 0x62, 0x74, 0x42, 0xA2, 0xCF, 0xAD, 0x0A, 0x0E,
    0xD7, 0xCE, 0x2C, 0xFA, 0xD3, 0xD4, 0x9C, 0x93, 0x26, 0xB0, 0xE3, 0x54,
    0xFF, 0x39, 0xC2, 0xED, 0x7C, 0x85, 0x10, 0x9E, 0xB9, 0x73, 0x89, 0xFD,
    0xBF, 0x14, 0xD4, 0x43, 0x01, 0x8C, 0x9C, 0x35, 0x0F, 0x42, 0xCA, 0xAE,
    0x2F, 0x38, 0x26, 0x90, 0xFF, 0x33, 0xF0, 0x7C, 0x9F, 0xEB, 0x32, 0x45,
    0xA1, 0x4B, 0x70, 0x00, 0xEF, 0xC4, 0x76, 0x56, 0x76, 0x92, 0xC1, 0xC9,
    0x91, 0xA4, 0xA4, 0x08, 0xB4, 0x8E, 0xC3, 0x0B, 0x05, 0xF8, 0x55, 0x34,
    0x34, 0x14, 0xCD, 0x38, 0xA5, 0xAB, 0x47, 0x94, 0x93, 0xA9, 0x5C, 0xAB,
    0x65, 0x74, 0xDA, 0x3D, 0x11, 0xF1, 0xDD, 0x1F, 0xBC, 0x83, 0x90, 0x7D,
    0x78, 0x58, 0x76, 0x01, 0x57, 0x85, 0xDF, 0xEF};

/* ****************************************************************** */
/* 3072 Bit Modulus */
/* ****************************************************************** */
/* RSA first prime */
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
    0x3a, 0x47, 0xe7, 0xaf, 0xb3, 0x15, 0x17, 0xf7, 0xc8, 0xdd, 0xf4, 0x93};

/* RSA second prime */
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
    0x1d, 0xd8, 0x69, 0x53, 0xa7, 0x10, 0x51, 0x00, 0x43, 0x23, 0xb3, 0xb1};

/* ****************************************************************** */
/* 4096 Bit Modulus */
/* ****************************************************************** */
/* RSA first prime */
static const Cpa8U p_4096[] = {
    0xBC, 0x6E, 0xA2, 0xA5, 0xFF, 0x94, 0x78, 0x50, 0x10, 0xB4, 0xA0, 0x91,
    0x5C, 0xC9, 0xC0, 0x51, 0xC0, 0x95, 0xB5, 0xEA, 0x5B, 0x9B, 0x7B, 0x81,
    0xD1, 0x65, 0x83, 0xEA, 0x14, 0x0C, 0xB5, 0x7F, 0x6D, 0x04, 0xEA, 0x73,
    0xA3, 0xE3, 0x76, 0xB5, 0x28, 0xA3, 0x93, 0x00, 0x23, 0xC8, 0xF4, 0xC0,
    0xF8, 0xD0, 0xB3, 0xA6, 0xD7, 0xE1, 0xA5, 0x49, 0x05, 0x94, 0xFA, 0x37,
    0x4B, 0x81, 0x6B, 0xEC, 0xD7, 0x82, 0x23, 0x55, 0x99, 0xE2, 0xCB, 0x45,
    0x08, 0x5C, 0x77, 0x8C, 0x29, 0x81, 0x77, 0xA0, 0x1E, 0x6C, 0x73, 0xE8,
    0xF4, 0x47, 0xCB, 0x31, 0xBC, 0x80, 0x60, 0x0C, 0xC5, 0xDC, 0xB0, 0x42,
    0x22, 0xB9, 0xC5, 0xA3, 0x8A, 0xB7, 0x58, 0x6A, 0x22, 0xD4, 0x85, 0x61,
    0x78, 0x31, 0x04, 0xCC, 0xBA, 0x8C, 0xDA, 0xA7, 0x73, 0x42, 0x80, 0x70,
    0xE3, 0xD4, 0x51, 0xEB, 0xD2, 0xF1, 0xFB, 0x93, 0x3A, 0x5B, 0x09, 0x9A,
    0x6E, 0xC3, 0x65, 0x95, 0xA8, 0x2B, 0x72, 0x68, 0xA2, 0x1A, 0xA7, 0x36,
    0x9C, 0x04, 0xAD, 0xDB, 0xDD, 0x1B, 0xAD, 0x9A, 0x83, 0x00, 0x73, 0x12,
    0xBF, 0xB4, 0xBE, 0x0D, 0xD4, 0x31, 0x42, 0xE8, 0x97, 0x1E, 0x10, 0x22,
    0x64, 0x64, 0x91, 0xD0, 0xB1, 0xF4, 0xA5, 0xFA, 0x70, 0x9A, 0x5E, 0xB5,
    0x9C, 0xF6, 0xA4, 0x9D, 0xE8, 0xEE, 0xD5, 0x36, 0x7A, 0x7B, 0xFF, 0x1B,
    0x26, 0x2D, 0x31, 0x53, 0x24, 0xC8, 0x24, 0x68, 0x4B, 0x32, 0x21, 0x51,
    0x1A, 0x78, 0xBD, 0xCA, 0xD5, 0xA4, 0xCF, 0xEA, 0xBC, 0xEC, 0x25, 0xB5,
    0x6A, 0x30, 0xD0, 0x5F, 0xF6, 0x3E, 0x34, 0x95, 0xF4, 0xD8, 0x60, 0x3B,
    0x59, 0x60, 0x75, 0xDC, 0x94, 0x5C, 0x3E, 0x4D, 0x5D, 0x1F, 0x37, 0x5A,
    0x7D, 0x58, 0x2F, 0x9A, 0x17, 0x0D, 0xF6, 0xAD, 0x29, 0xE6, 0x27, 0x63,
    0xA1, 0xDD, 0x8C, 0x4D};

/* RSA second prime */
static const Cpa8U q_4096[] = {
    0xBC, 0x6E, 0xA0, 0x6C, 0xF3, 0x64, 0xBA, 0xA6, 0x67, 0x32, 0x2C, 0x3E,
    0x2B, 0x6D, 0xC4, 0xD4, 0x2F, 0xC6, 0x88, 0x63, 0xFE, 0x41, 0x16, 0x4D,
    0xA8, 0x6C, 0x3D, 0xF3, 0x3B, 0xFD, 0x61, 0xE0, 0x58, 0xEC, 0xFE, 0xFE,
    0x7E, 0x4E, 0x5D, 0x0B, 0x01, 0x2A, 0xF6, 0x05, 0x11, 0x07, 0x97, 0xA4,
    0xB5, 0x1E, 0x87, 0x6B, 0x09, 0xE1, 0x51, 0x1F, 0x0B, 0xE0, 0x80, 0xC5,
    0x07, 0x8D, 0xD1, 0xC5, 0x14, 0xCE, 0x12, 0xFB, 0x35, 0xDA, 0x5D, 0x3E,
    0x8C, 0x0A, 0xA6, 0x16, 0x5B, 0x13, 0x36, 0xE5, 0x91, 0xAC, 0x5B, 0xC9,
    0x2D, 0xF4, 0x53, 0x26, 0xFA, 0xEF, 0xC2, 0x45, 0x94, 0xD7, 0xDA, 0x1D,
    0xBA, 0x39, 0xFA, 0x99, 0xA1, 0xE6, 0xCE, 0x49, 0x28, 0xFC, 0x44, 0x22,
    0xED, 0x39, 0x2B, 0xFB, 0xD2, 0x53, 0xCE, 0x5C, 0x53, 0x4A, 0xA9, 0xAE,
    0x7D, 0x72, 0xA0, 0x49, 0xB1, 0x63, 0x2A, 0x8A, 0x0C, 0x73, 0xDE, 0x98,
    0xE3, 0x98, 0x36, 0x6D, 0xC6, 0x64, 0xDE, 0x24, 0x88, 0x93, 0x3F, 0x6B,
    0xC5, 0xFD, 0xB2, 0xE9, 0x9D, 0x10, 0xFE, 0x15, 0xA7, 0x11, 0xA9, 0x92,
    0x79, 0x98, 0x0D, 0xF5, 0xC4, 0x2C, 0x16, 0xC8, 0x2E, 0x1D, 0x36, 0x5F,
    0x72, 0x6F, 0x5A, 0x06, 0x63, 0x4F, 0x71, 0xEA, 0x82, 0x96, 0x22, 0x75,
    0xAD, 0x59, 0xD7, 0x3E, 0x53, 0xE5, 0xE4, 0x92, 0x1C, 0x65, 0x76, 0x72,
    0xC3, 0xA2, 0xE2, 0xF0, 0xC6, 0x70, 0x11, 0x2B, 0x72, 0xF8, 0x6F, 0x43,
    0x20, 0x6B, 0xBC, 0xAE, 0x2F, 0xE2, 0xDF, 0x4D, 0x04, 0x06, 0x8E, 0x59,
    0xD6, 0xCA, 0x5F, 0x39, 0x05, 0xCC, 0xE0, 0xC2, 0x93, 0x81, 0x6F, 0xC0,
    0xA5, 0x5A, 0xB1, 0xE6, 0xCB, 0x31, 0x5E, 0xB7, 0x42, 0xD4, 0xEB, 0xCE,
    0x83, 0xE2, 0xAE, 0x46, 0x5F, 0xC5, 0x74, 0x31, 0x7D, 0x58, 0x47, 0xB7,
    0x84, 0x4E, 0xBF, 0x7B};


#if CY_API_VERSION_AT_LEAST(3, 0)
/*  add for SM3 and SM4  */
smx_key_size_pairs_t cipherSM4TestList[] = {
    { CPA_CY_SYM_CIPHER_SM4_ECB, KEY_SIZE_128_IN_BYTES, 0, 0 },
    { CPA_CY_SYM_CIPHER_SM4_CBC, KEY_SIZE_128_IN_BYTES, 0, 0 },
    { CPA_CY_SYM_CIPHER_SM4_CTR, KEY_SIZE_128_IN_BYTES, 0, 0 }
};

smx_key_size_pairs_t algChainSM4SM3TestList[] = {
    { CPA_CY_SYM_CIPHER_SM4_ECB,
      KEY_SIZE_128_IN_BYTES,
      CPA_CY_SYM_HASH_SM3,
      SM3_DIGEST_LENGTH_IN_BYTES },
    { CPA_CY_SYM_CIPHER_SM4_CBC,
      KEY_SIZE_128_IN_BYTES,
      CPA_CY_SYM_HASH_SM3,
      SM3_DIGEST_LENGTH_IN_BYTES },
    { CPA_CY_SYM_CIPHER_SM4_CTR,
      KEY_SIZE_128_IN_BYTES,
      CPA_CY_SYM_HASH_SM3,
      SM3_DIGEST_LENGTH_IN_BYTES },
};

int cipherSM4TestList_count =
    sizeof(cipherSM4TestList) / (sizeof(smx_key_size_pairs_t));
int algChainSM4SM3TestList_count =
    sizeof(algChainSM4SM3TestList) / (sizeof(smx_key_size_pairs_t));
#endif


Cpa32U getThroughput(Cpa64U numPackets, Cpa32U packetSize, perf_cycles_t cycles)
{
    unsigned long long bytesSent = 0;
    unsigned long long time = cycles;
    unsigned long long rate = 0;
    /* declare frequency in kiloHertz*/
    Cpa32U freq = sampleCodeGetCpuFreq();
    bytesSent = packetSize;
    bytesSent = bytesSent * numPackets;

    /*get time in milli seconds by dividing numberOfClockCycles by frequency
     * in kilohertz ie: cycles/(cycles/millsec) = time (mSec) */
    do_div(time, freq);
    /*check that the sample time was not to small*/
    if (time == 0)
    {
        /*if the sample time is too small, then we don't  have enough data
         * to calculate throughput, so we return 0 to the caller*/
        return 0;
    }
    /*set rate to be bytesSent, once we perform the do_div rate changes from
     * bytes to bytes/milli second or kiloBytes/second*/
    rate = bytesSent;
    /*rate in kBps*/
    do_div(rate, time);
    /*check that the rate is high enough to convert to Megabits per second*/
    if (rate == 0)
    {
        /*if the rate is too small to translate to Mbps then just return 0*/
        return 0;
    }
    /* convert Kilobytes/second to Kilobits/second*/
    rate = rate * NUM_BITS_IN_BYTE;
    /*then convert rate from Kilobits/second to Megabits/second*/
    do_div(rate, KILOBITS_IN_MEGABITS);
    return (Cpa32U)rate;
}

Cpa32U getOpsPerSecond(Cpa64U responses, perf_cycles_t cycles)
{
    unsigned long long time = cycles;
    unsigned long long freq = sampleCodeGetCpuFreq();
    /*multiply responses by 1000 so that we don't loose precision
     * precision is lost if we convert millisec to seconds to calculate
     * ops per second ie 2238 ms becomes 2 seconds the decimal place is lost*/
    unsigned long long opsPerSec = responses;
    opsPerSec = opsPerSec * MILLI_SECONDS_IN_SECOND;
    /*convert cycles into time(ms)*/
    do_div(time, freq);
    if (time == 0)
    {
        PRINT_ERR("Sample time is too small to calculate OpsPerSecond\n");
        return 0;
    }
    do_div(opsPerSec, time);
    return opsPerSec;
}
EXPORT_SYMBOL(getOpsPerSecond);

void accumulateAsymPerfData(Cpa32U numberOfThreads,
                            perf_data_t *performanceStats[],
                            perf_data_t *stats,
                            Cpa64U *buffersProcessed,
                            Cpa32U *responsesPerThread)
{
    Cpa32U i = 0;


    /*accumulate the responses into one perf_data_t structure*/
    for (i = 0; i < numberOfThreads; i++)
    {
        stats->responses += performanceStats[i]->responses;
        /*is the data was submitted in multiple buffers per list, then the
         * number of buffers processed is  number of responses multiplied
         * by the numberOfBuffers*/
        *buffersProcessed += performanceStats[i]->responses;
        stats->retries += performanceStats[i]->retries;
        stats->numOperations += performanceStats[i]->numOperations;
        if (iaCycleCount_g)
        {
            stats->offloadCycles += performanceStats[i]->offloadCycles;
        }
        *responsesPerThread = performanceStats[i]->responses;
        clearPerfStats(performanceStats[i]);
    }
}

CpaStatus printAsymStatsAndStopServices(thread_creation_data_t *data)
{
    Cpa32U i = 0;
    Cpa32U j = 0;
    Cpa32U k = 0;

    Cpa32U responsesPerThread = 0;
    perf_cycles_t numOfCycles = 0;
    perf_data_t stats = {0};
    perf_data_t *stats2;
    Cpa32U *perfDataDeviceOffsets;
    Cpa32U *threadCountPerDevice;
    perf_data_t **tempPerformanceStats;

    Cpa64U buffersProcessed = 0;
    Cpa32U opsPerSec = 0;
    Cpa32U devOpsperSec = 0;

    /*stop all crypto instances, There is no other place we can stop CyServices
     * as all other function run in thread context and its not safe to call
     * stopCyServices in thread context, otherwise we could stop threads that
     * have requests in flight. This function is called by the framework
     * after all threads have completed*/
    stopCyServices();
    stats2 = qaeMemAlloc(sizeof(perf_data_t) * (packageIdCount_g + 1));
    if (NULL == stats2)
    {
        PRINT_ERR("Unable to allocate memory for stats2\n");
        return CPA_STATUS_FAIL;
    }
    perfDataDeviceOffsets =
        qaeMemAlloc(sizeof(Cpa32U) * (packageIdCount_g + 1));
    if (NULL == perfDataDeviceOffsets)
    {
        qaeMemFree((void **)&stats2);
        PRINT_ERR("Unable to allocate memory for perfDataDeviceOffsets\n");
        return CPA_STATUS_FAIL;
    }

    threadCountPerDevice = qaeMemAlloc(sizeof(Cpa32U) * (packageIdCount_g + 1));
    if (NULL == threadCountPerDevice)
    {
        qaeMemFree((void **)&stats2);
        qaeMemFree((void **)&perfDataDeviceOffsets);
        PRINT_ERR("Unable to allocate memory for threadCountPerDevice\n");
        return CPA_STATUS_FAIL;
    }
    tempPerformanceStats =
        qaeMemAlloc(sizeof(perf_data_t *) * data->numberOfThreads);
    if (NULL == tempPerformanceStats)
    {
        qaeMemFree((void **)&stats2);
        qaeMemFree((void **)&perfDataDeviceOffsets);
        qaeMemFree((void **)&threadCountPerDevice);
        PRINT_ERR("Error in allocating memory for tempPerformanceStats\n");
        return CPA_STATUS_FAIL;
    }
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_FAIL == data->performanceStats[i]->threadReturnStatus)
        {
            qaeMemFree((void **)&stats2);
            qaeMemFree((void **)&perfDataDeviceOffsets);
            qaeMemFree((void **)&threadCountPerDevice);
            qaeMemFree((void **)&tempPerformanceStats);
            return CPA_STATUS_FAIL;
        }
    }

    /* Block to re-group the data per device */
    for (j = 0; j < (packageIdCount_g + 1); j++)
    {
        for (i = 0; i < data->numberOfThreads; i++)
        {
            if (data->performanceStats[i]->packageId == j)
            {
                tempPerformanceStats[k++] = data->performanceStats[i];
            }
        }
    }
    for (i = 0; i < data->numberOfThreads; i++)
    {
        data->performanceStats[i] = tempPerformanceStats[i];
#ifdef LATENCY_CODE
        if (latency_enable)
        {
            /* accumulate latency for all devices */
            stats.aveLatency += data->performanceStats[i]->aveLatency;
            if (data->performanceStats[i]->maxLatency > stats.maxLatency)
            {
                stats.maxLatency = data->performanceStats[i]->maxLatency;
            }
            if (data->performanceStats[i]->minLatency < stats.minLatency)
            {
                stats.minLatency = data->performanceStats[i]->minLatency;
            }
            else
            {
                if (stats.minLatency == 0)
                {
                    stats.minLatency = data->performanceStats[i]->minLatency;
                }
            }
        }
#endif
    }
    memset(stats2, 0, sizeof(perf_data_t) * (packageIdCount_g + 1));
    stats.averagePacketSizeInBytes = data->packetSize;
    getLongestCycleCount2(stats2,
                          data->performanceStats,
                          data->numberOfThreads,
                          perfDataDeviceOffsets,
                          threadCountPerDevice);
    for (i = 0; i < (packageIdCount_g + 1); i++)
    {
        accumulateAsymPerfData(
            threadCountPerDevice[i],
            &(data->performanceStats[perfDataDeviceOffsets[i]]),
            &stats2[i],
            &buffersProcessed,
            &responsesPerThread);

        numOfCycles =
            (stats2[i].endCyclesTimestamp - stats2[i].startCyclesTimestamp);
        if (!signOfLife)
        {
            devOpsperSec = getOpsPerSecond(buffersProcessed, numOfCycles);
        }
        buffersProcessed = 0;
        opsPerSec += devOpsperSec;
        stats.numOperations += stats2[i].numOperations;
        stats.responses += stats2[i].responses;
        stats.retries += stats2[i].retries;
        if (iaCycleCount_g)
        {
            stats.offloadCycles += stats2[i].offloadCycles;
        }
    }
    numOfCycles = (stats.endCyclesTimestamp - stats.startCyclesTimestamp);
    PRINT("Number of Threads     %u\n", data->numberOfThreads);
    PRINT("Total Submissions     %llu\n",
          (unsigned long long)stats.numOperations);
    PRINT("Total Responses       %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries         %llu\n", (unsigned long long)stats.retries);
    if (!signOfLife)
    {
        PRINT("CPU Frequency(kHz)    %u\n", sampleCodeGetCpuFreq());
        PRINT("Operations per second %8u\n", opsPerSec);
        if (iaCycleCount_g)
        {
            do_div(stats.offloadCycles, data->numberOfThreads);
            PRINT("Avg Offload Cycles    %llu\n", stats.offloadCycles);
        }
#ifdef LATENCY_CODE
        if (latency_enable)
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /* Display how long it took on average to process a buffer in uSecs
             * Also include min/max to show variance */
            if (cpuFreqKHz != 0)
            {
                if (data->numberOfThreads != 0)
                {
                    do_div(stats.aveLatency, data->numberOfThreads);
                    statsLatency = 1000 * stats.minLatency;
                    do_div(statsLatency, cpuFreqKHz);
                    PRINT("Min. Latency (uSecs)     %llu\n", statsLatency);
                    statsLatency = 1000 * stats.aveLatency;
                    do_div(statsLatency, cpuFreqKHz);
                    PRINT("Ave. Latency (uSecs)     %llu\n", statsLatency);
                    statsLatency = 1000 * stats.maxLatency;
                    do_div(statsLatency, cpuFreqKHz);
                    PRINT("Max. Latency (uSecs)     %llu\n", statsLatency);
                }
            }
        }
#endif

    }
    qaeMemFree((void **)&stats2);
    qaeMemFree((void **)&perfDataDeviceOffsets);
    qaeMemFree((void **)&threadCountPerDevice);
    qaeMemFree((void **)&tempPerformanceStats);
    return CPA_STATUS_SUCCESS;
}

/*****************************************************************************
 * * @description
 * Poll the number of crypto operations
 * ***************************************************************************/
CpaStatus cyPollNumOperationsTimeout(perf_data_t *pPerfData,
                                     CpaInstanceHandle instanceHandle,
                                     Cpa64U numOperations,
                                     Cpa64U timeout)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    startCycles = sampleCodeTimestamp();

    while (pPerfData->responses != numOperations)
    {
        coo_poll_trad_cy(pPerfData, instanceHandle, &status);
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > timeout)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            PRINT("Responses expected = %llu, recieved = %llu\n",
                  (unsigned long long)numOperations,
                  (unsigned long long)pPerfData->responses);
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(cyPollNumOperationsTimeout);

/*****************************************************************************
 * * @description
 * Poll the number of crypto operations
 * ***************************************************************************/
CpaStatus cyPollNumOperations(perf_data_t *pPerfData,
                              CpaInstanceHandle instanceHandle,
                              Cpa64U numOperations)
{
    return cyPollNumOperationsTimeout(
        pPerfData, instanceHandle, numOperations, SAMPLE_CODE_WAIT_DEFAULT);
}
EXPORT_SYMBOL(cyPollNumOperations);

CpaStatus setCyPollWaitFn(Cpa32U poll_type, Cpa32U sleep_time)
{
    poll_type_g = poll_type;
    sleep_time_g = sleep_time;
    return CPA_STATUS_SUCCESS;
}

CpaStatus setCyPollInterval(Cpa32U interval)
{
    cyPollingThreadsInterval_g = interval;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setCyPollInterval);

void sampleCodePoll(CpaInstanceHandle instanceHandle_in)
{
    CpaStatus status = CPA_STATUS_FAIL;
    while (cy_service_started_g == CPA_TRUE)
    {
        /*poll for 0 means process all packets on the ET ring */
        status = icp_sal_CyPollInstance(instanceHandle_in, 0);
        if (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)
        {
            /* do nothing */
        }
        else
        {
            PRINT_ERR("WARNING icp_sal_CyPollInstance returned status %d\n",
                      status);
        }
        switch (poll_type_g)
        {
            case POLL_AND_SLEEP:
                sampleCodeSleepMilliSec(sleep_time_g);
                break;
            default:
                AVOID_SOFTLOCKUP_POLL;
        }
    }
    sampleCodeThreadExit();
}

/*start crypto acceleration service if its not already started*/
CpaStatus startCyServices(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32U nProcessorsOnline = 0;
    /*if the service started flag is false*/
    if (cy_service_started_g == CPA_FALSE)
    {
        /*start all crypto instances*/
        status = cpaCyGetNumInstances(&numInstances_g);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
            return status;
        }
        if (numInstances_g > 0)
        {
            cyInstances_g =
                qaeMemAlloc(sizeof(CpaInstanceHandle) * numInstances_g);
            if (NULL == cyInstances_g)
            {
                PRINT_ERR("Failed to allocate memory for instances\n");
                return CPA_STATUS_FAIL;
            }
            status = cpaCyGetInstances(numInstances_g, cyInstances_g);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
                qaeMemFree((void **)&cyInstances_g);
                return status;
            }
            /*start all instances*/
            for (i = 0; i < numInstances_g; i++)
            {
                status = cpaCySetAddressTranslation(
                    cyInstances_g[i], (CpaVirtualToPhysical)qaeVirtToPhysNUMA);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("Error setting memory config for instance %d\n",
                              i);
                    qaeMemFree((void **)&cyInstances_g);
                    return CPA_STATUS_FAIL;
                }
                status = cpaCyStartInstance(cyInstances_g[i]);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("Error starting crypto instance %d\n", i);
                    /*attempt to stop any started service, we don't check status
                     * as some instances may not have been started and this
                     * might return fail*/
                    stopCyServices();
                    qaeMemFree((void **)&cyInstances_g);
                    return CPA_STATUS_FAIL;
                }
            }
        }
        else
        {
            PRINT("There are no crypto instances available\n");
            return CPA_STATUS_FAIL;
        }
    }

    /*set the started flag to true*/
    cy_service_started_g = CPA_TRUE;
    /*determine number of cores on system and limit the number of cores to be
     *used to be the smaller of the numberOf Instances or the number of cores*/
    nProcessorsOnline = sampleCodeGetNumberOfCpus();
    if (nProcessorsOnline > numInstances_g)
    {
        setCoreLimit(numInstances_g);
    }
    /*status should be success if we get to here*/
    return status;
}

/*stop all crypto services*/
CpaStatus stopCyServices(void)
{
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaStatus returnStatus = CPA_STATUS_SUCCESS;
    /*stop only if the services are in a started state*/
    if (cy_service_started_g == CPA_TRUE)
    {
        /*stop all instances*/
        for (i = 0; i < numInstances_g; i++)
        {

            status = cpaCyStopInstance(cyInstances_g[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Could not stop instance: %d\n", i);
                /*if we fail to stop a service then something odd has happened
                 * internally and its probably best to reboot*/
                PRINT_ERR("Internal error has occur which probably can only ");
                PRINT(" be fixed by a reboot\n");
                returnStatus = CPA_STATUS_FAIL;
            }
        }
        /*set the service started flag to false*/
        cy_service_started_g = CPA_FALSE;
    }

    /*free the polling threads*/
    if (cy_polling_started_g == CPA_TRUE)
    {
        /* set polling flag to false */
        cy_polling_started_g = CPA_FALSE;
        /* Wait for all threads_g to complete */
        for (i = 0; i < numPolledInstances_g; i++)
        {
            sampleCodeThreadJoin(&pollingThread_g[i]);
        }
        if (0 < numPolledInstances_g)
        {
            qaeMemFree((void **)&pollingThread_g);
            numPolledInstances_g = 0;
        }
    }
    if (cyInstances_g != NULL)
    {
        qaeMemFree((void **)&cyInstances_g);
        cyInstances_g = NULL;
    }
    return returnStatus;
}

CpaStatus sampleCreateBuffers(CpaInstanceHandle instanceHandle,
                              Cpa32U packetSizeInBytes[],
                              CpaFlatBuffer *pFlatBuffArray[],
                              CpaBufferList *pBuffListArray[],
                              symmetric_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    Cpa32U createBufferCount = 0;
    Cpa32U createListCount = 0;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U node = 0;
    Cpa32U numBufferLists = setup->numBuffLists;
    Cpa32U numBuffers = 0;
    Cpa32U bufferSizeInBytes = 0;
    CpaFlatBuffer *pTempFlatBuffArray = NULL;
    Cpa32U lastBufferInListSize = 0;


    if (NULL == pFlatBuffArray)
    {
        PRINT_ERR("pFlatBuffArray is NULL\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == pBuffListArray)
    {
        PRINT_ERR("pBuffListArray is NULL\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == packetSizeInBytes)
    {
        PRINT_ERR("packetSizeInBytes is NULL\n");
        return CPA_STATUS_FAIL;
    }
    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get node for instance\n");
        return CPA_STATUS_FAIL;
    }
    /* Calculate number of flatbuffers in one list */
    if (0 == setup->flatBufferSizeInBytes)
    {
        numBuffers = NUM_UNCHAINED_BUFFERS;
    }
    else
    {
        numBuffers = (packetSizeInBytes[0] -
                      setup->setupData.hashSetupData.digestResultLenInBytes) /
                     setup->flatBufferSizeInBytes;
        if ((setup->enableRoundOffPkt == CPA_TRUE) &&
            ((lastBufferInListSize =
                  ((packetSizeInBytes[0] -
                    setup->setupData.hashSetupData.digestResultLenInBytes) %
                   setup->flatBufferSizeInBytes)) != 0))
        {
            numBuffers++;
        }

    }
    /*
     * calculate memory size which is required for pPrivateMetaData
     * member of CpaBufferList
     */
    status =
        cpaCyBufferListGetMetaSize(instanceHandle, numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyBufferListGetMetaSize Failed with status: %d\n",
                  status);
        return status;
    }

    /*allocate memory for bufferLists, FlatBuffers and Data*/
    for (createListCount = 0; createListCount < numBufferLists;
         createListCount++)
    {
        /* Allocate memory for temp flat buffer Array*/
        pTempFlatBuffArray = qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == pTempFlatBuffArray)
        {
            PRINT_ERR("Could not allocate pFlatBuffArray[%u]\n",
                      createListCount);
            sampleFreeBuffers(pFlatBuffArray, pBuffListArray, setup);
            return CPA_STATUS_FAIL;
        }

        pFlatBuffArray[createListCount] = pTempFlatBuffArray;
        /* Allocate pData memory for each flat buffer */
        for (createBufferCount = 0; createBufferCount < numBuffers;
             createBufferCount++)
        {
            /* Decide flat buffers Size: if setup->flatBufferSizeInBytes is 0
             * for the IMIX case,
             * there is only single buffer in List, and bufferSizeInBytes is
             * equal to packetSizeInBytes */
            if (0 == setup->flatBufferSizeInBytes)
            {
                /*bufferSize includes space for the digest in the case of hash
                 * or alg chain*/
                bufferSizeInBytes = packetSizeInBytes[createListCount];
            }
            /*while not the last buffer, allocate the normal flat buffer size*/
            else if (createBufferCount != numBuffers - 1)
            {
                bufferSizeInBytes = setup->flatBufferSizeInBytes;
            }
            /*else allocate flat buffer + space for digest*/
            else
            {
                if ((setup->enableRoundOffPkt == CPA_TRUE) &&
                    (lastBufferInListSize != 0))
                {
                    bufferSizeInBytes =
                        lastBufferInListSize +
                        setup->setupData.hashSetupData.digestResultLenInBytes;
                }
                else
                {
                    bufferSizeInBytes =
                        setup->flatBufferSizeInBytes +
                        setup->setupData.hashSetupData.digestResultLenInBytes;
                }
            }

            /* Allocate aligned memory for specified packet size on the node
             * that the thread is running on*/
            pTempFlatBuffArray[createBufferCount].pData =
                qaeMemAllocNUMA(bufferSizeInBytes, node, BYTE_ALIGNMENT_64);
            if (NULL == pTempFlatBuffArray[createBufferCount].pData)
            {
                PRINT_ERR(
                    "Failed to allocate flatBuffer[%u].pData:(%u) memory\n",
                    createBufferCount,
                    bufferSizeInBytes);
                sampleFreeBuffers(pFlatBuffArray, pBuffListArray, setup);
                return CPA_STATUS_FAIL;
            }
            /*initialize dataLenInBytes for each flat buffer*/
            pTempFlatBuffArray[createBufferCount].dataLenInBytes =
                bufferSizeInBytes;

            /*populate the data source with random data*/
            generateRandomData(pTempFlatBuffArray[createBufferCount].pData,
                               bufferSizeInBytes);
        }

        /*allocate memory for bufferLists, FlatBuffers and Data*/
        /* Allocate memory for pPrivateMetaData */
        pBufferMeta = qaeMemAllocNUMA(bufferMetaSize, node, BYTE_ALIGNMENT_64);
        if (NULL == pBufferMeta)
        {
            PRINT_ERR("Failed to allocate pBufferMeta memory\n");
            sampleFreeBuffers(pFlatBuffArray, pBuffListArray, setup);
            return CPA_STATUS_FAIL;
        }

        /* Allocate memory for buffer list structure */
        pBuffListArray[createListCount] =
            qaeMemAllocNUMA(sizeof(CpaBufferList), node, BYTE_ALIGNMENT_64);
        if (NULL == pBuffListArray[createListCount])
        {
            PRINT_ERR("Failed to allocate bufferlist memory\n");
            sampleFreeBuffers(pFlatBuffArray, pBuffListArray, setup);
            qaeMemFreeNUMA((void **)&pBufferMeta);
            return CPA_STATUS_FAIL;
        }

        /*
         * Fill in elements of buffer list struct.
         * For this scenario- each buffer list only
         * contains one buffer
         */
        pBuffListArray[createListCount]->numBuffers = numBuffers;
        pBuffListArray[createListCount]->pPrivateMetaData = pBufferMeta;

        /* set up the pBuffers pointer */
        pBuffListArray[createListCount]->pBuffers = pTempFlatBuffArray;
    } /* end of pre allocated buffer for loop */

/*
 * Return CPA_STATUS_SUCCESS if all buffers have
 * been correctly allocated
 */
    return CPA_STATUS_SUCCESS;
}

void sampleFreeBuffers(CpaFlatBuffer *srcBuffPtrArray[],
                       CpaBufferList *srcBuffListArray[],
                       symmetric_test_params_t *setup)
{
    Cpa32U freeMemListCount = 0;
    Cpa32U freeMemCount = 0;
    CpaFlatBuffer *pTempFlatBuffArray = NULL;

    for (freeMemListCount = 0; freeMemListCount < setup->numBuffLists;
         freeMemListCount++)
    {
        /* Check if bufferListArray is NULL */
        if (NULL == srcBuffListArray)
        {
            break;
        }
        /* Check if bufferList is NULL */
        if (NULL != srcBuffListArray[freeMemListCount])
        {
            /* Free pPrivateMetaData if it's not NULL */
            if (NULL != srcBuffListArray[freeMemListCount]->pPrivateMetaData)
            {
                qaeMemFreeNUMA(
                    &srcBuffListArray[freeMemListCount]->pPrivateMetaData);
            }
            if (NULL == srcBuffPtrArray)
            {
                break;
            }
            pTempFlatBuffArray = srcBuffPtrArray[freeMemListCount];
            /*
             * Loop through and free all buffers that have been
             * pre-allocated.
             */
            for (freeMemCount = 0;
                 freeMemCount < srcBuffListArray[freeMemListCount]->numBuffers;
                 freeMemCount++)
            {

                if (NULL != pTempFlatBuffArray)
                {
                    if (NULL != pTempFlatBuffArray[freeMemCount].pData)
                    {
                        qaeMemFreeNUMA(
                            (void **)&pTempFlatBuffArray[freeMemCount].pData);
                    }
                }
            }
            qaeMemFreeNUMA((void **)&srcBuffPtrArray[freeMemListCount]);
            qaeMemFreeNUMA((void **)&srcBuffListArray[freeMemListCount]);
        }
    }
}
/**
 *****************************************************************************
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 *  function to free buffer list for symmetric crypto sample code
 ******************************************************************************/
void dpSampleFreeBuffers(CpaBufferList **srcBuffListArray,
                         CpaPhysBufferList **srcPhyBuffListArray,
                         Cpa32U numBuffLists,
                         Cpa32U numBuffers)
{
    Cpa32U freeMemListCount = 0;
    Cpa32U freeMemCount = 0;
    CpaFlatBuffer *pTempFlatBuffArray = NULL;

    for (freeMemListCount = 0; freeMemListCount < numBuffLists;
         freeMemListCount++)
    {
        /* Check if bufferListArray is NULL */
        if (NULL != srcBuffListArray)
        {
            /* Check if bufferList is NULL */
            if (NULL != srcBuffListArray[freeMemListCount])
            {
                /* Free pPrivateMetaData if it's not NULL */
                if (NULL !=
                    srcBuffListArray[freeMemListCount]->pPrivateMetaData)
                {
                    qaeMemFreeNUMA(
                        &srcBuffListArray[freeMemListCount]->pPrivateMetaData);
                }

                pTempFlatBuffArray =
                    srcBuffListArray[freeMemListCount]->pBuffers;
                /*
                 * Loop through and free all buffers that have been
                 * pre-allocated.
                 */
                for (freeMemCount = 0; freeMemCount < numBuffers;
                     freeMemCount++)
                {

                    if (NULL != pTempFlatBuffArray)
                    {
                        if (NULL != pTempFlatBuffArray[freeMemCount].pData)
                        {
                            qaeMemFreeNUMA(
                                (void **)&pTempFlatBuffArray[freeMemCount]
                                    .pData);
                        }
                    }
                }
                if (NULL != pTempFlatBuffArray)
                {
                    qaeMemFreeNUMA((void **)&pTempFlatBuffArray);
                }

                qaeMemFreeNUMA((void **)&srcBuffListArray[freeMemListCount]);
            }
        }
        if (NULL != srcPhyBuffListArray)
        {
            if (NULL != srcPhyBuffListArray[freeMemListCount])
            {
                qaeMemFreeNUMA((void **)&srcPhyBuffListArray[freeMemListCount]);
            }
        }
    }
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 *  function to create buffer list for symmetric crypto sample code
 ******************************************************************************/
CpaStatus dpSampleCreateBuffers(CpaInstanceHandle instanceHandle,
                                Cpa32U packetSizeInBytesArray[],
                                CpaBufferList *pBuffListArray[],
                                CpaPhysBufferList *pPhyBuffListArray[],
                                symmetric_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    Cpa32U createBufferCount = 0;
    Cpa32U createListCount = 0;
    Cpa8U *pBufferMeta = NULL;
    Cpa32U node = 0;
    CpaFlatBuffer *pFlatBuffArray = NULL;
    Cpa32U bufferSizeInBytes = 0;
    Cpa32U numBufferLists = setup->numBuffLists;
    Cpa32U numBuffers = 0;
    Cpa32U lastBufferInListSize = 0;

    if (NULL == pBuffListArray)
    {
        PRINT_ERR("pBuffListArray is NULL\n");
        return CPA_STATUS_FAIL;
    }
    if (NULL == packetSizeInBytesArray)
    {
        PRINT_ERR("packetSizeInBytesArray is NULL\n");
        return CPA_STATUS_FAIL;
    }
    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get node for instance\n");
        return CPA_STATUS_FAIL;
    }
    if (setup->isTLS)
    {
        /*
         * For TLS, single buffer is used for getting better performance.
         * The first 13 bytes contains the header and the remaining
         * buffer contains the payload+mac+padding.
         */
        numBuffers = NUM_UNCHAINED_BUFFERS;
    }
    else
    {

        /* Calculate number of flatbuffers in one list */
        if (0 == setup->flatBufferSizeInBytes)
        {
            numBuffers = NUM_UNCHAINED_BUFFERS;
        }
        /* if packet size is not align with block size of cipher,
         * we need to some padding data into the buffers. */
        else
        {
            numBuffers =
                (packetSizeInBytesArray[0] -
                 setup->setupData.hashSetupData.digestResultLenInBytes) /
                setup->flatBufferSizeInBytes;
            lastBufferInListSize =
                (packetSizeInBytesArray[0] -
                 setup->setupData.hashSetupData.digestResultLenInBytes) %
                setup->flatBufferSizeInBytes;
            if (setup->enableRoundOffPkt == CPA_TRUE &&
                lastBufferInListSize != 0)
            {
                numBuffers++;
            }
        }
    }
    /*
     * calculate memory size which is required for pPrivateMetaData
     * member of CpaBufferList
     */
    status =
        cpaCyBufferListGetMetaSize(instanceHandle, numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyBufferListGetMetaSize Failed with status: %d\n",
                  status);
        return status;
    }

    for (createListCount = 0; createListCount < numBufferLists;
         createListCount++)
    {
        /*allocate memory for bufferLists and Data*/
        /* Allocate memory for temp flat buffer Array*/
        pFlatBuffArray = qaeMemAllocNUMA(
            sizeof(CpaFlatBuffer) * numBuffers, node, BYTE_ALIGNMENT_64);
        if (NULL == pFlatBuffArray)
        {
            PRINT_ERR("Could not allocate pFlatBuffArray[%u]\n",
                      createListCount);
            dpSampleFreeBuffers(
                pBuffListArray, pPhyBuffListArray, createListCount, numBuffers);
            return CPA_STATUS_FAIL;
        }

        /* Allocate memory for pPrivateMetaData */
        pBufferMeta = qaeMemAllocNUMA(bufferMetaSize, node, BYTE_ALIGNMENT_64);
        if (NULL == pBufferMeta)
        {
            PRINT_ERR("Failed to allocate pBufferMeta memory\n");
            dpSampleFreeBuffers(
                pBuffListArray, pPhyBuffListArray, createListCount, numBuffers);
            return CPA_STATUS_FAIL;
        }

        /* Allocate memory for buffer list structure */
        pBuffListArray[createListCount] =
            qaeMemAllocNUMA(sizeof(CpaBufferList), node, BYTE_ALIGNMENT_64);
        if (NULL == pBuffListArray[createListCount])
        {
            PRINT_ERR("Failed to allocate bufferlist memory\n");
            dpSampleFreeBuffers(
                pBuffListArray, pPhyBuffListArray, createListCount, numBuffers);
            qaeMemFreeNUMA((void **)&pBufferMeta);
            return CPA_STATUS_FAIL;
        }
        /*
         * Fill in elements of buffer list struct.
         * For this scenario- each buffer list only
         * contains one buffer
         */
        pBuffListArray[createListCount]->numBuffers = numBuffers;
        pBuffListArray[createListCount]->pPrivateMetaData = pBufferMeta;

        /* set up the pBuffers pointer */
        pBuffListArray[createListCount]->pBuffers = pFlatBuffArray;

        /* Allocate memory for physical flat buffer list structure
         * total size of one Buffer list should be equal to size
         * sizeof(CpaPhysBufferList) + sizeof(CpaPhysFlatBuffer)* numBuffers */
        pPhyBuffListArray[createListCount] = qaeMemAllocNUMA(
            sizeof(CpaPhysBufferList) + sizeof(CpaPhysFlatBuffer) * numBuffers,
            node,
            BYTE_ALIGNMENT_64);
        if (NULL == pPhyBuffListArray[createListCount])
        {
            PRINT_ERR("Failed to allocate bufferlist memory\n");
            dpSampleFreeBuffers(
                pBuffListArray, pPhyBuffListArray, createListCount, numBuffers);
            return CPA_STATUS_FAIL;
        }
        pPhyBuffListArray[createListCount]->numBuffers =
            pBuffListArray[createListCount]->numBuffers;
        /* Allocate pData memory for each flat buffer */
        for (createBufferCount = 0; createBufferCount < numBuffers;
             createBufferCount++)
        {
            /* Decide flat buffers Size: if setup->flatBufferSizeInBytes is 0,
             * there is only single buffer in List, and bufferSizeInBytes is
             * equal to packetSizeInBytes */
            if (setup->isTLS)
            {
                /* For TLS, single flat buffer is used and the
                 * flatBufferSizeInBytes is filled in the setup API.
                 * The flatBufferSizeInBytes includes Header +
                 * Packet + Mac.
                 */
                if (0 == setup->flatBufferSizeInBytes)
                {
                    bufferSizeInBytes = packetSizeInBytesArray[createListCount];
                }
                else
                {
                    bufferSizeInBytes = setup->flatBufferSizeInBytes;
                }
            }
            else
            {

                if (0 == setup->flatBufferSizeInBytes)
                {
                    bufferSizeInBytes = packetSizeInBytesArray[createListCount];
                }
                else if (createBufferCount != numBuffers - 1)
                {
                    bufferSizeInBytes = setup->flatBufferSizeInBytes;
                }
                /*else allocate flat buffer + space for digest*/
                else
                {
                    if ((setup->enableRoundOffPkt == CPA_TRUE) &&
                        (lastBufferInListSize != 0))
                    {
                        bufferSizeInBytes = lastBufferInListSize +
                                            setup->setupData.hashSetupData
                                                .digestResultLenInBytes;
                    }
                    else
                    {
                        bufferSizeInBytes = setup->flatBufferSizeInBytes +
                                            setup->setupData.hashSetupData
                                                .digestResultLenInBytes;
                    }
                }
            }
            /* Allocate aligned memory for specified packet size on the node
             * that the thread is running on*/
            pFlatBuffArray[createBufferCount].pData =
                qaeMemAllocNUMA(bufferSizeInBytes, node, BYTE_ALIGNMENT_64);
            if (NULL == pFlatBuffArray[createBufferCount].pData)
            {
                PRINT_ERR(
                    "Failed to allocate flatBuffer[%u].pData:(%u) memory\n",
                    createBufferCount,
                    bufferSizeInBytes);
                dpSampleFreeBuffers(pBuffListArray,
                                    pPhyBuffListArray,
                                    createListCount,
                                    numBuffers);
                return CPA_STATUS_FAIL;
            }
            /*initialize dataLenInBytes for each flat buffer*/
            pFlatBuffArray[createBufferCount].dataLenInBytes =
                bufferSizeInBytes;

            /*populate the data source with random data*/
            generateRandomData(pFlatBuffArray[createBufferCount].pData,
                               bufferSizeInBytes);

            pPhyBuffListArray[createListCount]
                ->flatBuffers[createBufferCount]
                .bufferPhysAddr = (CpaPhysicalAddr)virtAddrToDevAddr(
                (SAMPLE_CODE_UINT *)(uintptr_t)pFlatBuffArray[createBufferCount]
                    .pData,
                instanceHandle,
                CPA_ACC_SVC_TYPE_CRYPTO);
            pPhyBuffListArray[createListCount]
                ->flatBuffers[createBufferCount]
                .dataLenInBytes =
                pFlatBuffArray[createBufferCount].dataLenInBytes;
        }
    } /* end of pre allocated buffer for loop */

/*
 * Return CPA_STATUS_SUCCESS if all buffers have
 * been correctly allocated
 */
    return CPA_STATUS_SUCCESS;
}

void setCpaFlatBufferMSB(CpaFlatBuffer *buf)
{
    buf->pData[0] |= MSB_SETTING;
}
EXPORT_SYMBOL(setCpaFlatBufferMSB);

/*Function assumes each number is the same length in bytes*/
CpaBoolean isFbALessThanFbB(CpaFlatBuffer *pFbA, CpaFlatBuffer *pFbB)
{
    Cpa32U i = 0;

    for (i = 0; i < pFbA->dataLenInBytes; i++)
    {
        if (pFbA->pData[i] < pFbB->pData[i])
        {
            return CPA_TRUE;
        }
        else if (pFbB->pData[i] < pFbA->pData[i])
        {
            return CPA_TRUE;
        }
        /*continue if equal*/
    }
    /*buffers contain the same number*/
    return CPA_FALSE;
}

/*Function assumes each number is the same length in bytes*/
CpaFlatBuffer *findSmallestNumber(CpaFlatBuffer *numbers, Cpa32U numNumbers)
{
    CpaFlatBuffer *result = numbers;
    Cpa32U i = 0;

    for (i = 0; i < numNumbers; i++)
    {
        if (CPA_TRUE == isFbALessThanFbB(result, &numbers[i]))
        {
            result = &numbers[i];
        }
    }
    return result;
}

void makeParam1SmallerThanParam2(Cpa8U *param1,
                                 Cpa8U *param2,
                                 Cpa32U len,
                                 CpaBoolean msbSettingRequired)
{
    Cpa32U i = 0;
    int startLen = 0;
    if (msbSettingRequired == CPA_TRUE)
    {

        /*set startLen = 1 so that next for loop starts
         * at 1 rather than 0, we handle element 0 here*/
        startLen = 1;
        /*Ignoring MSB, if param2 is less then param1, and param2 is not 0,
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
        /* else Param1 is smaller than param2 so set i = len to skip next for
         * loop*/
        else
        {
            return;
        }
    }
    for (i = startLen; i < len; i++)
    {
        /*if param2 is less then param1, and param2 is not 0, then make param1
         *  to be smaller than param2, and we are done*/
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

void conformMillerRabinData(CpaFlatBuffer *pMR,
                            CpaFlatBuffer *pSmallestPC,
                            Cpa32U rounds)
{
    Cpa32S difference = 0;
    Cpa8U mrLength = 0;
    Cpa32U i = 0;
    /* Get the length of the Miller Rabin Data */
    mrLength = pMR->dataLenInBytes / rounds;

    /* Get the difference in buffer length of the Miller Rabin round and the
     * smallest Prime candidate
     */
    difference = mrLength - pSmallestPC->dataLenInBytes;

    /* As there's a limit on the smallest buffer size used to contain the Miller
     * Rabin Data(MAX(64,required_buffer_size)), we still must satisfy the
     * conditions that Miller Rabin data is >1 and less than Prime -1.
     * If the Miller Rabin buffer length is greater than the smallest Prime
     * Candidate buffer length, we need to zero the most significant bytes of
     * the difference and then ensure that the actual data length is the same.
     */
    if (difference > 0)
    {
        for (i = 0; i < rounds; i++)
        {
            memset(pMR->pData + (i * mrLength), 0, difference);
            /* Ensure that Miller Rabin data is less than Prime -1 */
            makeParam1SmallerThanParam2(pMR->pData + (i * mrLength) +
                                            difference,
                                        pSmallestPC->pData,
                                        pSmallestPC->dataLenInBytes,
                                        CPA_FALSE);
        }
    }
    else
    {
        for (i = 0; i < rounds; i++)
        {
            makeParam1SmallerThanParam2(pMR->pData +
                                            (i * pSmallestPC->dataLenInBytes),
                                        pSmallestPC->pData,
                                        pSmallestPC->dataLenInBytes,
                                        CPA_FALSE);
        }
    }
}

/*assumption is that primeCandidate is an odd number*/
static void incrementPrimeCandidate(CpaFlatBuffer *primeCandidate)
{
    Cpa32S i = 0;

    /*increment by 2 to keep the primeCandidate odd*/
    if (primeCandidate->pData[primeCandidate->dataLenInBytes - 1] != 0xFF)
    {
        primeCandidate->pData[primeCandidate->dataLenInBytes - 1] += INC_BY_TWO;
        /*roll over did not occur we can exit*/
        return;
    }
    primeCandidate->pData[primeCandidate->dataLenInBytes - 1] = 1;
    /*other wise roll over occurred and we need to increment the high order
     * bytes*/
    for (i = primeCandidate->dataLenInBytes - SECOND_LAST_BYTE; i >= 0; i--)
    {
        /*if the byte is not 0xff then roll over wont occur, and we
         * can increment and exit*/
        if (primeCandidate->pData[i] != 0xFF)
        {
            /*we can increment high order bytes by 1 because it does not
             * effect odd/even*/
            primeCandidate->pData[i] += 1;
            break;
        }
        else
        {
            primeCandidate->pData[i] = 0;
        }
    }
}

void primeCallback(void *pCallbackTag,
                   CpaStatus status,
                   void *pOpData,
                   CpaBoolean testPassed)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT("status not successful\n");
    }
    if (NULL == pOpData)
    {
        PRINT("pOpData is NULL\n");
    }

    /*check perf_data pointer is valid*/
    if (pPerfData == NULL)
    {
        PRINT_ERR("Invalid data in CallbackTag\n");
        return;
    }
    /* response has been received */
    pPerfData->responses++;
    /*if we have received the pre-set numOperations, then get the clock cycle
     * as a timestamp and post the Semaphore to release parent thread*/
    if (testPassed == CPA_TRUE)
    {
        /*record the index of the prime candidate where the primeCandidate
         * passed the primeTest, averagePacketSize in bytes
         * is not the most logical variable to use,  we are re-using the
         * averagePacketSizeInBytes member for a completely different purpose
         * In this case we want to know how many requests it took to find a
         * prime number so that we can be sure we have set the
         * NUM_PRIME_GENERATION_ATTEMPTS so that we find a prime 99.9% of the
         * time*/
        pPerfData->averagePacketSizeInBytes = pPerfData->responses;
    }
    if (pPerfData->numOperations == pPerfData->responses)
    {
        /*let calling thread know that we are done*/
        sampleCodeSemaphorePost(&pPerfData->comp);
    }
}

void generatePrimeCandidates(CpaFlatBuffer *primeCandidate, Cpa32U numCandiates)
{
    Cpa32U i = 0;
    /*generate a random number to test for prime*/
    generateRandomData(primeCandidate[0].pData,
                       primeCandidate[0].dataLenInBytes);
    /*make sure MSB is set*/
    setCpaFlatBufferMSB(&primeCandidate[0]);
    /*at the very least prime number candidate should be odd, so we perform
     * OR bitwise operation to make sure value is odd*/
    primeCandidate[0].pData[primeCandidate[0].dataLenInBytes - 1] |= 1;

    /*create set of primeCandidates starting with an odd number and
     * each subsequent candidate is incremented by 2*/
    for (i = 1; i < numCandiates; i++)
    {
        memcpy(primeCandidate[i].pData,
               primeCandidate[i - 1].pData,
               primeCandidate[i - 1].dataLenInBytes);
        incrementPrimeCandidate(&primeCandidate[i]);
    }
}

/*****************************************************************************
 * frees any memory allocated in the generatePrime function
 *****************************************************************************/
#define FREE_GENPRIME_MEM()                                                    \
    do                                                                         \
    {                                                                          \
        Cpa32U j = 0;                                                          \
        qaeMemFreeNUMA((void **)&pPrimeTestOpData);                            \
        qaeMemFreeNUMA((void **)&pMillerRabinData);                            \
        for (j = 0; j < NUM_PRIME_GENERATION_ATTEMPTS; j++)                    \
        {                                                                      \
            qaeMemFreeNUMA((void **)&primeCandidates[j].pData);                \
        }                                                                      \
        qaeMemFreeNUMA((void **)&primeCandidates);                             \
    } while (0)

CpaStatus generatePrime(CpaFlatBuffer *primeCandidate,
                        CpaInstanceHandle cyInstanceHandle,
                        asym_test_params_t *setup)
{
    Cpa32U i = 0;
    Cpa32U attempt = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    /** Default is false (meaning the number is not a prime), except if the
     *  test explicitly says it is probably a prime */
    CpaBoolean testPassed = CPA_FALSE;
    perf_data_t primePerfData = {0};

    /** Structure containing the operational data */
    CpaCyPrimeTestOpData *pPrimeTestOpData = NULL;
    CpaFlatBuffer *primeCandidates = NULL;
    /** Random numbers for Miller-Rabin */
    CpaFlatBuffer pMR = {0};
    CpaFlatBuffer *smallestPC = NULL;
    Cpa8U *pMillerRabinData = NULL;
    Cpa8U *pMillerRabinRound[NB_MR_ROUNDS] = {0};
    Cpa32U millerRabinDataLen = 0;
    Cpa32U node = 0;
#ifdef POLL_INLINE
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    CpaBoolean isPolled = CPA_FALSE;
#endif
    millerRabinDataLen = primeCandidate->dataLenInBytes;
    /* The QA API has a a limit on the minimum size( 64 bytes) of the buffer
     * used to contain the Miller Rabin Round data.
     */
    MR_PRIME_LEN(millerRabinDataLen);
#ifdef POLL_INLINE
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(setup->cyInstanceHandle, instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
    }
    isPolled = instanceInfo2->isPolled;
    qaeMemFree((void **)&instanceInfo2);
#endif
    status = sampleCodeCyGetNode(cyInstanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return CPA_STATUS_FAIL;
    }
    primeCandidates =
        qaeMemAllocNUMA(sizeof(CpaFlatBuffer) * NUM_PRIME_GENERATION_ATTEMPTS,
                        node,
                        BYTE_ALIGNMENT_64);
    if (NULL == primeCandidates)
    {
        PRINT_ERR("primeCandidates is NULL\n");
        return CPA_STATUS_FAIL;
    }
    pPrimeTestOpData = qaeMemAllocNUMA(sizeof(CpaCyPrimeTestOpData) *
                                           NUM_PRIME_GENERATION_ATTEMPTS,
                                       node,
                                       BYTE_ALIGNMENT_64);
    if (NULL == pPrimeTestOpData)
    {
        PRINT_ERR("pPrimeTestOpData is NULL\n");
        FREE_GENPRIME_MEM();
        return CPA_STATUS_FAIL;
    }
    for (i = 0; i < NUM_PRIME_GENERATION_ATTEMPTS; i++)
    {
        status = bufferDataMemAlloc(cyInstanceHandle,
                                    &primeCandidates[i],
                                    primeCandidate->dataLenInBytes,
                                    NULL,
                                    0);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Could not allocate buffer\n");
            FREE_GENPRIME_MEM();
            return CPA_STATUS_FAIL;
        }
    }

    /*generate random numbers for miller rabin rounds*/
    pMillerRabinData = qaeMemAllocNUMA(
        millerRabinDataLen * NB_MR_ROUNDS, node, BYTE_ALIGNMENT_64);
    if (NULL == pMillerRabinData)
    {
        PRINT_ERR("Could not allocate memory for pMillerRabinData\n");
        FREE_GENPRIME_MEM();
        return CPA_STATUS_FAIL;
    }
    generateRandomData(pMillerRabinData, millerRabinDataLen * NB_MR_ROUNDS);
    /*set pointer to each miller rabin rounds number*/
    for (i = 0; i < NB_MR_ROUNDS; i++)
    {
        Cpa32U byteCheck = millerRabinDataLen - 1;
        pMillerRabinRound[i] = &pMillerRabinData[i * millerRabinDataLen];
        /*make sure the number is greater than 1 (quick check)*/
        if (1 >= pMillerRabinRound[i][byteCheck])
        {
            generateRandomData(&(pMillerRabinRound[i][byteCheck]), 1);
            /*In case of failure of the random number generator!*/
            if (1 >= pMillerRabinRound[i][byteCheck])
            {
                pMillerRabinRound[i][byteCheck] += INC_BY_TWO;
            }
        }
    }
    pMR.pData = pMillerRabinData;
    pMR.dataLenInBytes = millerRabinDataLen * NB_MR_ROUNDS;
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not allocate pMR pData\n");
        FREE_GENPRIME_MEM();
        return CPA_STATUS_FAIL;
    }

    for (i = 0; i < NUM_PRIME_GENERATION_ATTEMPTS; i++)
    {
        /* Populate the structure containing the data about the number to test:
         * - the number of which we want to test the primality
         * - its length
         * - perform a GCD Primality Test
         * - perform a Fermat Primality Test
         * - number of Miller-Rabin rounds to perform (from 0 to 50)
         * - Miller-Rabin random numbers (one for each test)
         * - perform a Lucas Primality Test */
        pPrimeTestOpData[i].primeCandidate.pData = primeCandidates[i].pData;
        pPrimeTestOpData[i].primeCandidate.dataLenInBytes =
            primeCandidates[i].dataLenInBytes;
        pPrimeTestOpData[i].performGcdTest = CPA_TRUE;
        pPrimeTestOpData[i].performFermatTest = CPA_TRUE;
        pPrimeTestOpData[i].numMillerRabinRounds = NB_MR_ROUNDS;
        pPrimeTestOpData[i].millerRabinRandomInput.pData = pMR.pData;

        pPrimeTestOpData[i].millerRabinRandomInput.dataLenInBytes =
            pMR.dataLenInBytes;
        pPrimeTestOpData[i].performLucasTest = CPA_TRUE;
    }
    /*Each of miller rabin round number has to be greater than 1 and
     * smaller than the number to test -1 */
    for (attempt = 0; attempt < NUM_PRIME_GENERATION_RETRY_ATTEMPTS; attempt++)
    {
        /*we will use the averagePacketSize to store the index of what passes
         * as a prime number in our array of prime candidates*/
        primePerfData.averagePacketSizeInBytes =
            NUM_PRIME_GENERATION_ATTEMPTS + 1;
        primePerfData.numOperations = NUM_PRIME_GENERATION_ATTEMPTS;
        primePerfData.responses = 0;
        /* Completion used in callback */
        sampleCodeSemaphoreInit(&primePerfData.comp, 0);
        generatePrimeCandidates(primeCandidates, NUM_PRIME_GENERATION_ATTEMPTS);
        /*no need to regenerate randomness - MR rounds just have to be
          greater than 1 and less than (Prime -1)*/
        /*Find smallest prime candidate*/
        smallestPC =
            findSmallestNumber(primeCandidates, NUM_PRIME_GENERATION_ATTEMPTS);
        /*make all numbers less than the smallest candidate -1 */
        smallestPC->pData[smallestPC->dataLenInBytes - 1] &= ~1;

        conformMillerRabinData(&pMR, smallestPC, NB_MR_ROUNDS);

        smallestPC->pData[smallestPC->dataLenInBytes - 1] |= 1;
        for (i = 0; i < NUM_PRIME_GENERATION_ATTEMPTS; i++)
        {
            do
            {
                status = cpaCyPrimeTest(
                    cyInstanceHandle,
                    primeCallback,        /* CB function */
                    &primePerfData,       /* callback tag */
                    &pPrimeTestOpData[i], /* operation data */
                    &testPassed);         /* return value:
                                            true if the number is probably
                                            a prime, false if it is not a prime */
                AVOID_SOFTLOCKUP;
                if (CPA_STATUS_RETRY == status)
                {
                    primePerfData.retries++;
#ifdef POLL_INLINE
                    if (poll_inline_g)
                    {
                        if (isPolled)
                        {
                            icp_sal_CyPollInstance(setup->cyInstanceHandle, 0);
                        }
                    }
#endif
                    if (RETRY_LIMIT == primePerfData.retries)
                    {
                        primePerfData.retries = 0;
                        AVOID_SOFTLOCKUP;
                    }
                }
            } while (CPA_STATUS_RETRY == status ||
                     CPA_STATUS_RESOURCE == status);
            /*we check for resource error above because if the driver is
             * testing a lot of large primes, it can run out of memory pools.
             * In this circumstance it can be reported as a
             * CPA_STATUS_RESOURCE*/
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT("Error Generating Prime\n");
                status = CPA_STATUS_FAIL;
                break;
            }
        }
        AVOID_SOFTLOCKUP;
/*the callback posts the semaphore when all requests have
 * been processed. If there was a fail, then the callback will never
 * receive the expected number of response and will never post the
 * semaphore*/
#ifdef POLL_INLINE
        if (poll_inline_g)
        {
            if ((CPA_STATUS_SUCCESS == status) && (isPolled))
            {
                /*
                ** Now need to wait for all the inflight Requests.
                */
                status = cyPollNumOperationsTimeout(&primePerfData,
                                                    setup->cyInstanceHandle,
                                                    primePerfData.numOperations,
                                                    SAMPLE_CODE_WAIT_PRIMES);
            }
        }
#endif
        if (CPA_STATUS_SUCCESS == status)
        {
            if (sampleCodeSemaphoreWait(&primePerfData.comp,
                                        SAMPLE_CODE_WAIT_DEFAULT) !=
                CPA_STATUS_SUCCESS)
            {
                PRINT_ERR("timeout or interruption in cpaCyPrimeTest\n");
                status = CPA_STATUS_FAIL;
            }
        }
        sampleCodeSemaphoreDestroy(&primePerfData.comp);
        /*here we re-use averagePacketSizeInBytes for another purpose. In this
         * case we use it to record the index in our primeNumber candidates
         * that a prime was found
         * if the index has changed then we have found a prime number*/
        if (primePerfData.averagePacketSizeInBytes !=
            NUM_PRIME_GENERATION_ATTEMPTS + 1)
        {
            memcpy(primeCandidate->pData,
                   primeCandidates[primePerfData.averagePacketSizeInBytes - 1]
                       .pData,
                   primeCandidate->dataLenInBytes);
            break;
        }
        else if (i == NUM_PRIME_GENERATION_ATTEMPTS - 1 &&
                 attempt == NUM_PRIME_GENERATION_RETRY_ATTEMPTS - 1 &&
                 primePerfData.averagePacketSizeInBytes ==
                     NUM_PRIME_GENERATION_ATTEMPTS + 1)
        {
            PRINT_ERR("\nPRIME NUMBER NOT FOUND\n");
            status = CPA_STATUS_FAIL;
        }
    }

    /** Free all allocated structures before exit*/
    FREE_GENPRIME_MEM();
    return status;
}
#undef FREE_GENPRIME_MEM
EXPORT_SYMBOL(generatePrime);

CpaStatus generateHardCodedPrime1P(CpaFlatBuffer *primeCandidate,
                                   asym_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U modulusLenInBytes = setup->modulusSizeInBytes;

    if ((CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_1 == setup->rsaKeyRepType) ||
        (CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2 == setup->rsaKeyRepType))
    {

        if (modulusLenInBytes == (MODULUS_512_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_512, sizeof(p_512));
        }
        else if (modulusLenInBytes == (MODULUS_1024_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_1024, sizeof(p_1024));
        }
        else if (modulusLenInBytes == (MODULUS_1536_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_1536, sizeof(p_1536));
        }
        else if (modulusLenInBytes == (MODULUS_2048_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_2048, sizeof(p_2048));
        }
        else if (modulusLenInBytes == (MODULUS_3072_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_3072, sizeof(p_3072));
        }
        else if (modulusLenInBytes == (MODULUS_4096_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, p_4096, sizeof(p_4096));
        }
    }
    else
    {
        if (modulusLenInBytes == (MODULUS_768_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_768, sizeof(m_768));
        }
        else if (modulusLenInBytes == (MODULUS_1024_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_1024, sizeof(m_1024));
        }
        else if (modulusLenInBytes == (MODULUS_1536_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_1536, sizeof(m_1536));
        }
        else if (modulusLenInBytes == (MODULUS_2048_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_2048, sizeof(m_2048));
        }
        else if (modulusLenInBytes == (MODULUS_3072_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_3072, sizeof(m_3072));
        }
        else if (modulusLenInBytes == (MODULUS_4096_BIT / NUM_BITS_IN_BYTE))
        {
            memcpy(primeCandidate->pData, m_4096, sizeof(m_4096));
        }
    }
    return status;
}
EXPORT_SYMBOL(generateHardCodedPrime1P);

CpaStatus generateHardCodedPrime2Q(CpaFlatBuffer *primeCandidate,
                                   asym_test_params_t *setup)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U modulusLenInBytes = setup->modulusSizeInBytes;

    if (modulusLenInBytes == (MODULUS_512_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_512, sizeof(q_512));
    }
    else if (modulusLenInBytes == (MODULUS_1024_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_1024, sizeof(q_1024));
    }
    else if (modulusLenInBytes == (MODULUS_1536_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_1536, sizeof(q_1536));
    }
    else if (modulusLenInBytes == (MODULUS_2048_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_2048, sizeof(q_2048));
    }
    else if (modulusLenInBytes == (MODULUS_3072_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_3072, sizeof(q_3072));
    }
    else if (modulusLenInBytes == (MODULUS_4096_BIT / NUM_BITS_IN_BYTE))
    {
        memcpy(primeCandidate->pData, q_4096, sizeof(q_4096));
    }

    return status;
}

void freeArrayFlatBufferNUMA(CpaFlatBuffer *buf, Cpa32U numBuffs)
{
    Cpa32U i = 0;

    /* this function maybe called before some memory is allocated,
     * in which case we just return */
    if (NULL == buf)
    {
        return;
    }
    for (i = 0; i < numBuffs; i++)
    {
        FREE_NUMA_MEM(buf[i].pData);
    }
    // PRINT("%d, S %p\n", __LINE__, buf);
    qaeMemFree((void **)&buf);
}

/*set hash len based on hash algorithm*/
Cpa32U setHashDigestLen(CpaCySymHashAlgorithm hashAlgorithm)
{
    switch (hashAlgorithm)
    {
        case CPA_CY_SYM_HASH_MD5:
            return MD5_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA1:
            return SHA1_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA224:
            return SHA224_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA256:
            return SHA256_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA384:
            return SHA384_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA512:
            return SHA512_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_AES_XCBC:
            return AES_XCBC_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_AES_CCM:
            return AES_CCM_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_AES_GCM:
        case CPA_CY_SYM_HASH_AES_GMAC:
            return AES_GCM_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_KASUMI_F9:
            return KASUMI_F9_DIGEST_RESULT_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SNOW3G_UIA2:
            return SNOW3G_UIA2_DIGEST_RESULT_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_AES_CMAC:
            return AES_CMAC_DIGEST_LENGTH_IN_BYTES;
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
        case CPA_CY_SYM_HASH_AES_CBC_MAC:
            return AES_CBC_MAC_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_ZUC_EIA3:
            return ZUC_EIA3_DIGEST_LENGTH_IN_BYTES;
        case CPA_CY_SYM_HASH_SHA3_256:
            return SHA3_DIGEST_256_LENGTH_IN_BYTES;
#elif CPA_CY_API_VERSION_NUM_MINOR >= 8
        case CPA_CY_SYM_HASH_AES_CBC_MAC:
            return AES_CBC_MAC_DIGEST_LENGTH_IN_BYTES;
#endif
        default:
            PRINT_ERR("Unknown hash algorithm\n");
            /*we return 0, when the the API is called it should fail with
             * invalid param*/
            return 0;
    }
}
EXPORT_SYMBOL(setHashDigestLen);

/*get hash block len for partial packet based on hash algorithm*/
Cpa32U getHashPartialPacketSize(CpaCySymHashAlgorithm hashAlgorithm,
                                Cpa32U packetSize)
{
    Cpa32U returnPacketSize = 0;
    Cpa32U blockSize = 0;
    Cpa32U delta = 0;

    switch (hashAlgorithm)
    {
        case CPA_CY_SYM_HASH_MD5:
            blockSize = MD5_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA1:
            blockSize = SHA1_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA224:
            blockSize = SHA_224_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA256:
            blockSize = SHA_256_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA384:
            blockSize = SHA_384_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA512:
            blockSize = SHA_512_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_AES_XCBC:
            blockSize = AES_XCBC_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SNOW3G_UIA2:
            blockSize = SNOW3G_UIA2_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_ZUC_EIA3:
            blockSize = ZUC_EIA3_BLOCK_LENGTH_IN_BYTES;
            break;
        case CPA_CY_SYM_HASH_SHA3_256:
            blockSize = SHA3_256_BLOCK_LENGTH_IN_BYTES;
            break;
        default:
            blockSize = packetSize;
            break;
    }

    if (packetSize < blockSize)
    {
        returnPacketSize = blockSize;
        PRINT("Packet Size is less than the block size for "
              "algo[%0d].So,scaling up to block size[%0d]\n",
              hashAlgorithm,
              packetSize);
    }
    else
    {
        delta = packetSize % blockSize;
        if (delta != 0)
        {
            returnPacketSize = packetSize - delta;
            PRINT("Packet Size is not multiple of block size for "
                  "algo[%0d].So,scaling down to block size[%0d]\n",
                  hashAlgorithm,
                  packetSize);
        }
        else
        {
            returnPacketSize = packetSize;
        }
    }

    return returnPacketSize;
}
EXPORT_SYMBOL(getHashPartialPacketSize);

/*****************************************************************************
 * frees any memory allocated in the calcDigest function
 *****************************************************************************/
#define FREE_CALC_DIGEST_MEM()                                                 \
    do                                                                         \
    {                                                                          \
        qaeMemFreeNUMA((void **)&pSrcBuffer);                                  \
        qaeMemFreeNUMA((void **)&pBufferList);                                 \
        qaeMemFreeNUMA((void **)&pBufferMeta);                                 \
        qaeMemFreeNUMA((void **)&pOpData);                                     \
        qaeMemFreeNUMA((void **)&pSessionCtx);                                 \
    } while (0)

/*calculate digest of msg using hashAlg and place it in digest*/
CpaStatus calcDigest(CpaInstanceHandle instanceHandle,
                     CpaFlatBuffer *msg,
                     CpaFlatBuffer *digest,
                     CpaCySymHashAlgorithm hashAlg)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaStatus ret = CPA_STATUS_SUCCESS;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    CpaCySymSessionSetupData sessionSetupData = {0};

    Cpa8U *pBufferMeta = NULL;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferList = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    CpaCySymOpData *pOpData = NULL;
    Cpa32U bufferSize = 0;
    Cpa32U digestLenInBytes = 0;
    Cpa32U numBuffers = 1; /* only using 1 buffer in this case */
    /* allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required. */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));
    Cpa8U *pSrcBuffer = NULL;
    Cpa32U node = 0;
    CpaCySymCbFunc symCb = NULL;
    perf_data_t *pPerfData = NULL;

#ifdef POLL_INLINE
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    CpaBoolean isPolled = CPA_FALSE;

    if (poll_inline_g)
    {
        pPerfData = qaeMemAlloc(sizeof(perf_data_t));
        if (NULL == pPerfData)
        {
            PRINT_ERR("Error: Allocating perf_data for calcDigest\n");
            return CPA_STATUS_FAIL;
        }
        pPerfData->numOperations = SINGLE_OPERATION;
        pPerfData->responses = 0;
        symCb = symPerformCallback;
    }
#endif

#ifdef POLL_INLINE
    instanceInfo2 = qaeMemAlloc(sizeof(CpaInstanceInfo2));
    if (instanceInfo2 == NULL)
    {
        PRINT_ERR("Failed to allocate memory for instanceInfo2");
        return CPA_STATUS_FAIL;
    }
    memset(instanceInfo2, 0, sizeof(CpaInstanceInfo2));

    if (poll_inline_g)
    {
        status = cpaCyInstanceGetInfo2(instanceHandle, instanceInfo2);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaCyInstanceGetInfo2 error, status: %d\n", status);
            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
    }
    isPolled = instanceInfo2->isPolled;
    qaeMemFree((void **)&instanceInfo2);
#endif
    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("sampleCodeCyGetNode failed with status %u\n", status);
        return CPA_STATUS_FAIL;
    }
    /* populate symmetric session data structure
     * for a plain hash operation */
    sessionSetupData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
    sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    sessionSetupData.hashSetupData.hashAlgorithm = hashAlg;
    sessionSetupData.hashSetupData.digestResultLenInBytes =
        setHashDigestLen(hashAlg);
    sessionSetupData.verifyDigest = CPA_FALSE;

    digestLenInBytes = sessionSetupData.hashSetupData.digestResultLenInBytes;
    bufferSize = msg->dataLenInBytes + digestLenInBytes;
    /* Determine size of session context to allocate */
    status = cpaCySymSessionCtxGetSize(
        instanceHandle, &sessionSetupData, &sessionCtxSize);
    /* Allocate session context */
    pSessionCtx = qaeMemAllocNUMA(sessionCtxSize, node, BYTE_ALIGNMENT_64);
    if (NULL == pSessionCtx)
    {
        PRINT_ERR("Could not allocate memory for pSessionCtx\n");
        return CPA_STATUS_FAIL;
    }

    status = cpaCySymInitSession(
        instanceHandle, symCb, &sessionSetupData, pSessionCtx);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySymInitSession failed with status %u\n", status);
        FREE_CALC_DIGEST_MEM();
        return status;
    }

    status =
        cpaCyBufferListGetMetaSize(instanceHandle, numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyBufferListGetMetaSize failed with status %u\n", status);
        FREE_CALC_DIGEST_MEM();
        return status;
    }
    pBufferMeta = qaeMemAllocNUMA(bufferMetaSize, node, BYTE_ALIGNMENT_64);
    if (NULL == pBufferMeta)
    {
        PRINT_ERR("could not allocate pBufferMeta\n");
        FREE_CALC_DIGEST_MEM();
        return CPA_STATUS_FAIL;
    }
    pBufferList = qaeMemAllocNUMA(bufferListMemSize, node, BYTE_ALIGNMENT_64);
    if (NULL == pBufferList)
    {
        PRINT_ERR("could not allocate pBufferMeta\n");
        FREE_CALC_DIGEST_MEM();
        return CPA_STATUS_FAIL;
    }
    pSrcBuffer = qaeMemAllocNUMA(bufferSize, node, BYTE_ALIGNMENT_64);
    if (NULL == pSrcBuffer)
    {
        PRINT_ERR("could not allocate pSrcBuffer\n");
        FREE_CALC_DIGEST_MEM();
        return CPA_STATUS_FAIL;
    }
    memcpy(pSrcBuffer, msg->pData, msg->dataLenInBytes);
    /*memory was allocated for bufferList and flatbuffer together so
     * the flatBuffer offset is just after the CpaBufferList*/
    pFlatBuffer = (CpaFlatBuffer *)(pBufferList + 1);
    pBufferList->pBuffers = pFlatBuffer;
    pBufferList->numBuffers = 1;
    pBufferList->pPrivateMetaData = pBufferMeta;
    pFlatBuffer->dataLenInBytes = bufferSize;
    pFlatBuffer->pData = pSrcBuffer;
    pOpData = qaeMemAllocNUMA(sizeof(CpaCySymOpData), node, BYTE_ALIGNMENT_64);
    if (NULL == pOpData)
    {
        PRINT_ERR("could not allocate pSrcBuffer\n");
        FREE_CALC_DIGEST_MEM();
        return CPA_STATUS_FAIL;
    }
    pOpData->sessionCtx = pSessionCtx;
    pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    pOpData->hashStartSrcOffsetInBytes = 0;
    pOpData->messageLenToHashInBytes = msg->dataLenInBytes;

    /* Place digest after data in the source buffer */
    pOpData->pDigestResult = pSrcBuffer + msg->dataLenInBytes;

/** Perform symmetric operation */
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        sampleCodeSemaphoreInit(&pPerfData->comp, 0);
    }
#endif
    status = cpaCySymPerformOp(instanceHandle,
                               pPerfData,   /* perform synchronous operation*/
                               pOpData,     /* operational data struct */
                               pBufferList, /* source buffer list */
                               pBufferList, /* in-place operation*/
                               NULL);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCySymPerformOp failed. (status = %u)\n", status);
        ret = CPA_STATUS_FAIL;
    }
#ifdef POLL_INLINE
    if (poll_inline_g)
    {
        if ((CPA_STATUS_SUCCESS == status) && (isPolled))
        {
            /*
            ** Now need to wait for all the inflight Requests.
            */
            status = cyPollNumOperations(
                pPerfData, instanceHandle, pPerfData->numOperations);
        }
        sampleCodeSemaphoreDestroy(&pPerfData->comp);
        qaeMemFree((void **)&pPerfData);
    }
#endif

    memcpy(digest->pData, pOpData->pDigestResult, digestLenInBytes);
    digest->dataLenInBytes = digestLenInBytes;

/* Remove the session - session init has already succeeded */
    status = removeSymSession(instanceHandle, pSessionCtx);

    FREE_CALC_DIGEST_MEM();

    return ret;
}

#undef FREE_CALC_DIGEST_MEM

CpaStatus removeSymSession(CpaInstanceHandle instanceHandle,
                           CpaCySymSessionCtx pSessionCtx)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

#if CY_API_VERSION_AT_LEAST(2, 2)
    /* In ASYNC mode we need to wait for
     * all pending request to be finished.
     */
    {
        CpaBoolean sessionInUse = CPA_FALSE;
        Cpa32U retries = 0;
        /*
         * We do a incremental sleep starting from 50 micro secs and
         * by incrementing the sleep time by twice the previous value
         * for each retry. Total sleep time would be 1.6 secs
         * for 15 number of retries which would be enough for all
         * inflight requests to get processed.
         */
        Cpa64U delay = REMOVE_SESSION_WAIT;
        static const Cpa16U maxRetries = 15;
        do
        {
            status = cpaCySymSessionInUse(pSessionCtx, &sessionInUse);
            if (CPA_STATUS_SUCCESS == status)
            {
                if (sessionInUse == CPA_TRUE)
                {
                    delay *= 2;
                    sleepNano(delay * 1000);
                    retries++;
                    if (retries >= maxRetries)
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else if (CPA_STATUS_UNSUPPORTED == status)
            {
                /* Mark success if sessionInUse not supported */
                status = CPA_STATUS_SUCCESS;
                break;
            }
            else
            {
                PRINT_ERR("cpaCySymSessionInUse: failed - status: %d\n",
                          status);
                status = CPA_STATUS_FAIL;
                break;
            }
        } while (1);
    }
#endif

    do
    {
        /* Linux: The session will only be removed if there are
         * no inflight requests. Until then, the function will
         * ask to retry. This should not result in infinite loop
         * as all inflight requests are guranteed to return even
         * in case of QAT failure or hang.
         * */
        status = cpaCySymRemoveSession(instanceHandle, pSessionCtx);
        sleepNano(REMOVE_SESSION_WAIT * 1000);
    } while (status == CPA_STATUS_RETRY);

    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Removal of session failed with status %d\n", status);
        status = CPA_STATUS_FAIL;
    }

    return status;
}
EXPORT_SYMBOL(removeSymSession);

/*allocate pData of buf*/
CpaStatus bufferDataMemAlloc(CpaInstanceHandle instanceHandle,
                             CpaFlatBuffer *buf,
                             Cpa32U size,
                             Cpa8U *copyData,
                             Cpa32U sizeOfCopyData)
{
    Cpa32U node = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    if (NULL == buf)
    {
        PRINT_ERR("buf is null\n");
        return CPA_STATUS_FAIL;
    }
    if ((NULL != copyData) && (sizeOfCopyData > size))
    {
        PRINT_ERR("copy size is > allocated size\n");
        return CPA_STATUS_FAIL;
    }
    /* get the node the thread is running on and allocate memory to the same
     * node
     */
    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS == status)
    {
        buf->pData = (Cpa8U *)qaeMemAllocNUMA(size, node, BYTE_ALIGNMENT_64);
        buf->dataLenInBytes = size;
        if (NULL == buf->pData)
        {
            PRINT_ERR("pData allocation error\n");
            return CPA_STATUS_FAIL;
        }
        if (NULL != copyData)
        {
            memcpy(buf->pData, copyData, size);
        }
    }
    else
    {
        PRINT_ERR("Failed to get node\n");
    }
    return status;
}

CpaStatus sampleCodeCyGetNode(CpaInstanceHandle instanceHandle, Cpa32U *node)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceInfo2 instanceInfo2;

    status = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
    if (status == CPA_STATUS_SUCCESS)
    {
        *node = instanceInfo2.nodeAffinity;
    }
    if (allocateMemOnOppositeNode)
    {
        *node = ~*node;
        *node = *node & 0x01;
    }
    return status;
}

void processCallback(void *pCallbackTag)
{
    perf_data_t *pPerfData = (perf_data_t *)pCallbackTag;
    /*check tag exists*/
    if (pCallbackTag == NULL)
    {
        PRINT_ERR("CallBack Tag is a Null pointer!!\n");
        return;
    }
    /* response has been received */
    pPerfData->responses++;
#ifdef LATENCY_CODE
    if (latency_enable && pPerfData->response_times != NULL)
    {
        /* Have we sampled too many buffer operations? */
        if (pPerfData->latencyCount > MAX_LATENCY_COUNT)
        {
            PRINT_ERR("pPerfData latencyCount > MAX_LATENCY_COUNT\n");
            return;
        }

        /* Is this the buffer we calculate latency on?
         * And have we calculated too many for array? */
        if (pPerfData->responses == pPerfData->nextCount)
        {
            int i = pPerfData->latencyCount;
            /* Now get the end timestamp - before any print outs */
            pPerfData->response_times[i] = sampleCodeTimestamp();

            pPerfData->nextCount += pPerfData->countIncrement;

            if (latency_debug)
                PRINT("%s: responses=%u, latencyCount=%d, end[i]:%llu, "
                      "start[i]:%llu, nextCount=%u\n",
                      __FUNCTION__,
                      (unsigned int)pPerfData->responses,
                      i,
                      pPerfData->response_times[i],
                      pPerfData->start_times[i],
                      pPerfData->nextCount);

            pPerfData->latencyCount++;
        }
    }
#endif // LATENCY_CODE
    if (iaCycleCount_g)
    {
        /*if we have received half our number of submissions back,
         * take a timestamp*/
        if (pPerfData->numOperations >> 1 == pPerfData->responses)
        {
            pPerfData->midCyclesTimestamp = sampleCodeTimestamp();
        }
    }
    /*if we have received the pre-set numOperations, then get the clock cycle
     * as a timestamp and post the Semaphore to release parent thread*/
    if (pPerfData->numOperations == pPerfData->responses)
    {
        pPerfData->endCyclesTimestamp = sampleCodeTimestamp();
        if (CPA_STATUS_SUCCESS != sampleCodeSemaphorePost(&pPerfData->comp))
        {
            PRINT_ERR("sampleCodeSemaphorePost Error\n");
            pPerfData->threadReturnStatus = CPA_STATUS_FAIL;
        }
    }
}

CpaStatus allocArrayOfPointers(CpaInstanceHandle instanceHandle,
                               void **buf,
                               Cpa32U numBuffs)
{
    Cpa32U node = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    status = sampleCodeCyGetNode(instanceHandle, &node);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Could not get Node\n");
        return CPA_STATUS_FAIL;
    }
    *buf =
        qaeMemAllocNUMA((sizeof(void *) * numBuffs), node, BYTE_ALIGNMENT_64);
    if (NULL != *buf)
    {
        memset(*buf, 0, (sizeof(void *) * numBuffs));
    }
    else
    {
        PRINT_ERR("Error getting allocating array of pointers \n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus allocArrayOfVirtPointers(void **buf, Cpa32U numBuffs)
{
    *buf = qaeMemAlloc((sizeof(void *) * numBuffs));
    if (NULL != *buf)
    {
        memset(*buf, 0, (sizeof(void *) * numBuffs));
    }
    else
    {
        PRINT_ERR("Error getting allocating array of pointers \n");
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(allocArrayOfVirtPointers);


CpaStatus waitForResponses(perf_data_t *perfData,
                           sync_mode_t syncMode,
                           Cpa32U numBuffers,
                           Cpa32U numLoops)
{
    Cpa64S responsesReceived = RESPONSE_NOT_CHECKED;
    CpaStatus status = CPA_STATUS_SUCCESS;

    if (SYNC == syncMode)
    {
        perfData->endCyclesTimestamp = sampleCodeTimestamp();
        sampleCodeSemaphorePost(&perfData->comp);
        perfData->responses = (Cpa64U)numBuffers * numLoops;
    }
    /*wait for the callback to receive all responses and free the
     * semaphore, or if in sync mode, the semaphore should already be free*/

    while (sampleCodeSemaphoreWait(&perfData->comp, SAMPLE_CODE_WAIT_DEFAULT) !=
           CPA_STATUS_SUCCESS)
    {
        if (RESPONSE_NOT_CHECKED != responsesReceived &&
            responsesReceived != (Cpa64S)perfData->numOperations &&
            responsesReceived == (Cpa64S)perfData->responses)
        {
            PRINT_ERR("System is not responding\n");
            PRINT("Responses expected/received: %llu/%llu\n",
                  (unsigned long long)perfData->numOperations,
                  (unsigned long long)perfData->responses);
            status = CPA_STATUS_FAIL;
            break;
        }
        else
        {
            responsesReceived = perfData->responses;
        }
    }

    return status;
}
CpaStatus cyCreatePollingThreadsIfPollingIsEnabled(void)
{
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa16U i = 0, j = 0, numCreatedPollingThreads = 0;
    Cpa32U coreAffinity = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    performance_func_t *pollFnArr = NULL;
#ifdef SC_CORE_NUM_POLICY
    Cpa32U numCores = 0;
    numCores = sampleCodeGetNumberOfCpus();
    if (numCores <= 0)
    {
        PRINT_ERR("sampleCodeGetNumberOfCpus() failed\n");
        return CPA_STATUS_FAIL;
    }
#endif
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
    int fd = -1;
#endif
    if (CPA_FALSE == cy_polling_started_g)
    {
        instanceInfo2 = qaeMemAlloc(numInstances_g * sizeof(CpaInstanceInfo2));
        if (NULL == instanceInfo2)
        {
            PRINT_ERR("Failed to allocate memory for pInstanceInfo2\n");
            return CPA_STATUS_FAIL;
        }
        pollFnArr = qaeMemAlloc(numInstances_g * sizeof(performance_func_t));
        if (NULL == pollFnArr)
        {
            PRINT_ERR("Failed to allocate memory for polling functions\n");

            qaeMemFree((void **)&instanceInfo2);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numInstances_g; i++)
        {
            status = cpaCyInstanceGetInfo2(cyInstances_g[i], &instanceInfo2[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                qaeMemFree((void **)&instanceInfo2);
                qaeMemFree((void **)&pollFnArr);
                return CPA_STATUS_FAIL;
            }
            pollFnArr[i] = NULL;
            if (CPA_TRUE == instanceInfo2[i].isPolled)
            {
                numPolledInstances_g++;
#if defined(USER_SPACE) && !defined(SC_EPOLL_DISABLED)
                status = icp_sal_CyGetFileDescriptor(cyInstances_g[i], &fd);
                if (CPA_STATUS_SUCCESS == status)
                {
                    pollFnArr[i] = sampleCodeCyEventPoll;
                    icp_sal_CyPutFileDescriptor(cyInstances_g[i], fd);
                    continue;
                }
                else if (CPA_STATUS_FAIL == status)
                {
                    PRINT_ERR("Error getting file descriptor for Event based "
                              "instance #%d\n",
                              i);
                    qaeMemFree((void **)&instanceInfo2);
                    qaeMemFree((void **)&pollFnArr);
                    return CPA_STATUS_FAIL;
                }
/* else feature is unsupported and sampleCodePoll() is to be
 * used.
 */
#endif
#if !defined(USER_SPACE)
                setCyPollWaitFn(1, 0);
#endif
                pollFnArr[i] = sampleCodePoll;
            }
        }
        if (0 == numPolledInstances_g)
        {
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_SUCCESS;
        }
        pollingThread_g =
            qaeMemAlloc(numPolledInstances_g * sizeof(sample_code_thread_t));
        if (NULL == pollingThread_g)
        {
            PRINT_ERR("Failed to allocate memory for polling threads\n");
            qaeMemFree((void **)&instanceInfo2);
            qaeMemFree((void **)&pollFnArr);
            return CPA_STATUS_FAIL;
        }
        for (i = 0; i < numInstances_g; i++)
        {
            if (NULL != pollFnArr[i])
            {
                status = sampleCodeThreadCreate(
                    &pollingThread_g[numCreatedPollingThreads],
                    NULL,
                    pollFnArr[i],
                    cyInstances_g[i]);
                if (status != CPA_STATUS_SUCCESS)
                {
                    PRINT_ERR("Error starting polling thread %d\n", status);
                    /*attempt to stop any started service, we don't check status
                     * as some instances may not have been started and this
                     * might return fail
                     * */
                    qaeMemFree((void **)&instanceInfo2);
                    qaeMemFree((void **)&pollFnArr);
                    return CPA_STATUS_FAIL;
                }
                /*loop of the instanceInfo coreAffinity bitmask to find the core
                 *  affinity*/
                for (j = 0; j < CPA_MAX_CORES; j++)
                {
                    if (CPA_BITMAP_BIT_TEST(instanceInfo2[i].coreAffinity, j))
                    {
#if defined(USER_SPACE)
                        coreAffinity = j;
#else
                        coreAffinity = j + 1;
#endif
                        break;
                    }
                }
#ifdef SC_CORE_NUM_POLICY
                if (numInstances_g % numCores == 0)
                {
                    /* To avoid recalculated and original core
                     * assignment equality */
                    coreAffinity =
                        (coreAffinity + numInstances_g + 1) % numCores;
                }
                else
                {
                    coreAffinity = (coreAffinity + numInstances_g) % numCores;
                }
#endif
                sampleCodeThreadBind(&pollingThread_g[numCreatedPollingThreads],
                                     coreAffinity);


                sampleCodeThreadStart(
                    &pollingThread_g[numCreatedPollingThreads]);

                numCreatedPollingThreads++;
            }
        }
        qaeMemFree((void **)&instanceInfo2);
        qaeMemFree((void **)&pollFnArr);

        cy_polling_started_g = CPA_TRUE;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(cyCreatePollingThreadsIfPollingIsEnabled);

CpaBoolean cyCheckAllInstancesArePolled(void)
{
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa16U i = 0;

    instanceInfo2 = qaeMemAlloc(numInstances_g * sizeof(CpaInstanceInfo2));
    if (NULL == instanceInfo2)
    {
        PRINT_ERR("Failed to allocate memory for pInstanceInfo2\n");
        return CPA_FALSE;
    }
    for (i = 0; i < numInstances_g; i++)
    {
        if (CPA_STATUS_SUCCESS !=
            cpaCyInstanceGetInfo2(cyInstances_g[i], &instanceInfo2[i]))
        {
            PRINT_ERR("Call to cpaCyInstanceGetInfo2 failed\n");
            qaeMemFree((void **)&instanceInfo2);
            return CPA_FALSE;
        }

        if (CPA_FALSE == instanceInfo2[i].isPolled)
        {
            qaeMemFree((void **)&instanceInfo2);
            return CPA_FALSE;
        }
    }
    qaeMemFree((void **)&instanceInfo2);
    return CPA_TRUE;
}

CpaStatus cyDpPollRemainingOperations(perf_data_t *pPerfData,
                                      CpaInstanceHandle instanceHandle)
{
    CpaStatus status = CPA_STATUS_FAIL;

    perf_cycles_t startCycles = 0, totalCycles = 0;
    Cpa32U freq = sampleCodeGetCpuFreq();
    startCycles = sampleCodeTimestamp();

    while (pPerfData->responses != pPerfData->numOperations)
    {
        status = icp_sal_CyPollDpInstance(instanceHandle, 0);
        if (CPA_STATUS_FAIL == status)
        {
            PRINT_ERR("Error polling instance\n");
            error_flag_g = CPA_TRUE;
            return CPA_STATUS_FAIL;
        }
        if (CPA_STATUS_RETRY == status)
        {
            AVOID_SOFTLOCKUP;
        }
        totalCycles = (sampleCodeTimestamp() - startCycles);
        if (totalCycles > 0)
        {
            do_div(totalCycles, freq);
        }

        if (totalCycles > SAMPLE_CODE_WAIT_DEFAULT)
        {
            PRINT_ERR("Timeout on polling remaining Operations\n");
            error_flag_g = CPA_TRUE;
            return CPA_STATUS_FAIL;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 *  function to print out cipher performance header
 ******************************************************************************/
void printCipherAlg(CpaCySymCipherSetupData cipherSetupData)
{
    switch (cipherSetupData.cipherAlgorithm)
    {
        case CPA_CY_SYM_CIPHER_NULL:
            PRINT("NULL");
            break;
        case CPA_CY_SYM_CIPHER_ARC4:
            PRINT("ARC4");
            break;
        case CPA_CY_SYM_CIPHER_AES_XTS:
            if (cipherSetupData.cipherKeyLenInBytes == KEY_SIZE_256_IN_BYTES)
            {
                PRINT("AES128-");
            }
            else if (cipherSetupData.cipherKeyLenInBytes ==
                     KEY_SIZE_512_IN_BYTES)
            {
                PRINT("AES256-");
            }
            PRINT("XTS");
            break;
        case CPA_CY_SYM_CIPHER_AES_ECB:
        case CPA_CY_SYM_CIPHER_AES_CBC:
        case CPA_CY_SYM_CIPHER_AES_CTR:
        case CPA_CY_SYM_CIPHER_AES_CCM:
        case CPA_CY_SYM_CIPHER_AES_GCM:
            if (cipherSetupData.cipherKeyLenInBytes == KEY_SIZE_128_IN_BYTES)
            {
                PRINT("AES128-");
            }
            else if (cipherSetupData.cipherKeyLenInBytes ==
                     KEY_SIZE_192_IN_BYTES)
            {
                PRINT("AES192-");
            }
            else if (cipherSetupData.cipherKeyLenInBytes ==
                     KEY_SIZE_256_IN_BYTES)
            {
                PRINT("AES256-");
            }
            else
            {
                PRINT("AES with unknown key size\n");
            }
            if (cipherSetupData.cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_ECB)
            {
                PRINT("ECB");
            }
            if (cipherSetupData.cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CBC)
            {
                PRINT("CBC");
            }
            if (cipherSetupData.cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CTR)
            {
                PRINT("CTR");
            }
            if (cipherSetupData.cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_CCM)
            {
                PRINT("CCM");
            }
            if (cipherSetupData.cipherAlgorithm == CPA_CY_SYM_CIPHER_AES_GCM)
            {
                PRINT("GCM");
            }
            break;
        case CPA_CY_SYM_CIPHER_DES_ECB:
            PRINT("DES-ECB");
            break;
        case CPA_CY_SYM_CIPHER_DES_CBC:
            PRINT("DES-CBC");
            break;
        case CPA_CY_SYM_CIPHER_3DES_ECB:
            PRINT("3DES-ECB");
            break;
        case CPA_CY_SYM_CIPHER_3DES_CBC:
            PRINT("3DES-CBC");
            break;
        case CPA_CY_SYM_CIPHER_3DES_CTR:
            PRINT("3DES-CTR");
            break;
        case CPA_CY_SYM_CIPHER_KASUMI_F8:
            PRINT("KASUMI_F8");
            break;
        case CPA_CY_SYM_CIPHER_SNOW3G_UEA2:
            PRINT("SNOW3G_UEA2");
            break;
        case CPA_CY_SYM_CIPHER_AES_F8:
            if (cipherSetupData.cipherKeyLenInBytes == KEY_SIZE_256_IN_BYTES)
            {
                PRINT("AES128-");
            }
            else if (cipherSetupData.cipherKeyLenInBytes ==
                     KEY_SIZE_384_IN_BYTES)
            {
                PRINT("AES192-");
            }
            else if (cipherSetupData.cipherKeyLenInBytes ==
                     KEY_SIZE_512_IN_BYTES)
            {
                PRINT("AES256-");
            }
            else
            {
                PRINT("AES with unknown key size\n");
            }
            PRINT("F8");
            break;
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
        case CPA_CY_SYM_CIPHER_ZUC_EEA3:
            PRINT("ZUC-EEA3");
            break;
        case CPA_CY_SYM_CIPHER_SM4_ECB:
            PRINT("SM4-ECB");
            break;
        case CPA_CY_SYM_CIPHER_SM4_CTR:
            PRINT("SM4-CTR");
            break;
        case CPA_CY_SYM_CIPHER_SM4_CBC:
            PRINT("SM4-CBC");
            break;
        case CPA_CY_SYM_CIPHER_CHACHA:
            PRINT("CHACHA");
            break;
#endif /*CPA_CY_API_VERSION_NUM_MAJOR >= 2*/
        default:
            PRINT("UNKNOWN_CIPHER %d\n", cipherSetupData.cipherAlgorithm);
            break;
    }
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * function to print out hash performance header
 ******************************************************************************/
void printHashAlg(CpaCySymHashSetupData hashSetupData)
{
    if (hashSetupData.hashMode == CPA_CY_SYM_HASH_MODE_AUTH &&
        !(hashSetupData.hashAlgorithm == CPA_CY_SYM_HASH_AES_XCBC ||
          hashSetupData.hashAlgorithm == CPA_CY_SYM_HASH_AES_CCM ||
          hashSetupData.hashAlgorithm == CPA_CY_SYM_HASH_AES_GCM ||
          hashSetupData.hashAlgorithm == CPA_CY_SYM_HASH_AES_GMAC ||
          hashSetupData.hashAlgorithm == CPA_CY_SYM_HASH_AES_CMAC))
    {
        PRINT("HMAC-");
    }
    switch (hashSetupData.hashAlgorithm)
    {
        case CPA_CY_SYM_HASH_MD5:
            PRINT("MD5");
            break;
        case CPA_CY_SYM_HASH_SHA1:
            PRINT("SHA1");
            break;
        case CPA_CY_SYM_HASH_SHA224:
            PRINT("SHA2-224");
            break;
        case CPA_CY_SYM_HASH_SHA256:
            PRINT("SHA2-256");
            break;
        case CPA_CY_SYM_HASH_SHA384:
            PRINT("SHA2-384");
            break;
        case CPA_CY_SYM_HASH_SHA512:
            PRINT("SHA2-512");
            break;
        case CPA_CY_SYM_HASH_AES_XCBC:
            PRINT("AES-XCBC");
            break;
        case CPA_CY_SYM_HASH_AES_CCM:
            PRINT("AES-CCM");
            break;
        case CPA_CY_SYM_HASH_AES_GCM:
            PRINT("AES-GCM");
            break;
        case CPA_CY_SYM_HASH_KASUMI_F9:
            PRINT("KASUMI-F9");
            break;
        case CPA_CY_SYM_HASH_SNOW3G_UIA2:
            PRINT("SNOW3G-UIA2");
            break;
        case CPA_CY_SYM_HASH_AES_CMAC:
            PRINT("AES-CMAC");
            break;
        case CPA_CY_SYM_HASH_AES_GMAC:
            PRINT("AES-GMAC");
            break;
#if CPA_CY_API_VERSION_NUM_MAJOR >= 2
        case CPA_CY_SYM_HASH_ZUC_EIA3:
            PRINT("ZUC-EIA3");
            break;
#elif CPA_CY_API_VERSION_NUM_MINOR >= 8
        case CPA_CY_SYM_HASH_AES_CBC_MAC:
            PRINT("AES-CBC-MAC");
            break;
#endif
        case CPA_CY_SYM_HASH_SM3:
            PRINT("SM3");
            break;
        default:
            PRINT("UNKNOWN_HASH\n");
            break;
    }
}
EXPORT_SYMBOL(printHashAlg);

CpaStatus stopCyServicesFromCallback(thread_creation_data_t *dummy_ptr)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* stop CY Services */
    status = stopCyServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Unable to stop CY services\n");
    }
    return status;
}
EXPORT_SYMBOL(stopCyServicesFromCallback);

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * print out performance test type
 ******************************************************************************/
void printSymTestType(symmetric_test_params_t *setup)
{
    if (setup->setupData.symOperation == CPA_CY_SYM_OP_CIPHER)
    {
        PRINT("Cipher ");
        printCipherAlg(setup->setupData.cipherSetupData);
    }
    else if (setup->setupData.symOperation == CPA_CY_SYM_OP_HASH)
    {
        PRINT("HASH ");
        printHashAlg(setup->setupData.hashSetupData);
    }
    else if (setup->setupData.symOperation == CPA_CY_SYM_OP_ALGORITHM_CHAINING)
    {
        PRINT("Algorithm Chaining - ");
        printCipherAlg(setup->setupData.cipherSetupData);
        PRINT(" ");
        printHashAlg(setup->setupData.hashSetupData);
    }
    PRINT("\n");
    PRINT("Direction             ");
    if (CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT ==
        setup->setupData.cipherSetupData.cipherDirection)
    {
        PRINT("Encrypt\n");
    }
    else
    {
        PRINT("Decrypt\n");
    }
    if (setup->isDpApi)
    {
        PRINT("API                   Data_Plane\n");
    }
    else
    {
        PRINT("API                   Traditional\n");
    }

}

void accumulateSymPerfData(Cpa32U numberOfThreads,
                           perf_data_t *performanceStats[],
                           perf_data_t *stats,
                           symmetric_test_params_t *setup,
                           Cpa64U *buffersProcessed,
                           Cpa32U *responsesPerThread)
{
    Cpa32U i = 0;


    /*accumulate the responses into one perf_data_t structure*/
    for (i = 0; i < numberOfThreads; i++)
    {
        if (!signOfLife)
        {
            if (iaCycleCount_g)
            {
                stats->offloadCycles += performanceStats[i]->offloadCycles;
            }
#ifdef LATENCY_CODE
            if (latency_enable)
            {
                /* Accumulate over all tests. Before using later we divide
                 * by number of threads: data->numberOfThreads*/
                stats->minLatency += performanceStats[i]->minLatency;
                stats->aveLatency += performanceStats[i]->aveLatency;
                stats->maxLatency += performanceStats[i]->maxLatency;
            }
#endif
        }
        stats->responses += performanceStats[i]->responses;
        /*is the data was submitted in multiple buffers per list, then the
         * number of buffers processed is  number of responses multiplied
         * by the numberOfBuffers*/
        if (setup->isMultiSGL)
        {
            *buffersProcessed +=
                performanceStats[i]->responses * setup->numBuffers;
        }
        else
        {
            *buffersProcessed += performanceStats[i]->responses;
        }
        stats->retries += performanceStats[i]->retries;
        stats->numOperations += performanceStats[i]->numOperations;
        *responsesPerThread = performanceStats[i]->responses;
        clearPerfStats(performanceStats[i]);
    }
}

/**
 *****************************************************************************
 * @ingroup sampleSymmetricPerf
 *
 * @description
 * print out performance data from a collection of threads that
 * were all running the same setup
 ******************************************************************************/
CpaStatus printSymmetricPerfDataAndStopCyService(thread_creation_data_t *data)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    perf_data_t stats = {0};
    perf_cycles_t numOfCycles = 0;
    Cpa32U responsesPerThread = 0;
    Cpa32U thoughputSize = 0;
    Cpa32U devThoughput = 0;
    Cpa32U throughput = 0;
    Cpa64U buffersProcessed = 0;
    Cpa32U i = 0;
    Cpa32U j = 0;
    Cpa32U k = 0;
    symmetric_test_params_t *setup = (symmetric_test_params_t *)data->setupPtr;
    Cpa32U *perfDataDeviceOffsets;
    Cpa32U *threadCountPerDevice;
    perf_data_t *stats2;
    perf_data_t **tempPerformanceStats = NULL;
    /*
        Cpa32U perfDataDeviceOffsets[packageIdCount_g];
        Cpa32U threadCountPerDevice[packageIdCount_g];
        perf_data_t stats2[packageIdCount_g];
    */



    /*stop crypto services if not already stopped, this is the only reasonable
     * location we can do this as this function is called after all threads are
     * complete*/
    status = stopCyServices();
    if (CPA_STATUS_SUCCESS != status)
    {
        /*no need to print error, stopCyServices already does it*/
        return status;
    }
    stats2 = qaeMemAlloc(sizeof(perf_data_t) * (packageIdCount_g + 1));
    if (NULL == stats2)
    {
        PRINT_ERR("Error allocating memory for performance stats\n");
        return CPA_STATUS_FAIL;
    }
    perfDataDeviceOffsets =
        qaeMemAlloc(sizeof(Cpa32U) * (packageIdCount_g + 1));
    if (NULL == perfDataDeviceOffsets)
    {
        PRINT_ERR("Error allocating memory for performance stats\n");
        qaeMemFree((void **)&stats2);
        return CPA_STATUS_FAIL;
    }
    threadCountPerDevice = qaeMemAlloc(sizeof(Cpa32U) * (packageIdCount_g + 1));
    if (NULL == threadCountPerDevice)
    {
        PRINT_ERR("Error allocating memory for performance stats\n");
        qaeMemFree((void **)&stats2);
        qaeMemFree((void **)&perfDataDeviceOffsets);
        return CPA_STATUS_FAIL;
    }
    tempPerformanceStats =
        qaeMemAlloc(sizeof(perf_data_t *) * data->numberOfThreads);
    if (NULL == tempPerformanceStats)
    {
        qaeMemFree((void **)&stats2);
        qaeMemFree((void **)&perfDataDeviceOffsets);
        qaeMemFree((void **)&threadCountPerDevice);
        PRINT_ERR("Error in allocating memory for tempPerformanceStats\n");
        return CPA_STATUS_FAIL;
    }
    for (i = 0; i < data->numberOfThreads; i++)
    {
        if (CPA_STATUS_FAIL == data->performanceStats[i]->threadReturnStatus)
        {
            qaeMemFree((void **)&stats2);
            qaeMemFree((void **)&perfDataDeviceOffsets);
            qaeMemFree((void **)&threadCountPerDevice);
            qaeMemFree((void **)&tempPerformanceStats);
            return CPA_STATUS_FAIL;
        }
    }
    /* Block to re-group the data per device */
    for (j = 0; j < (packageIdCount_g + 1); j++)
    {
        for (i = 0; i < data->numberOfThreads; i++)
        {
            if (data->performanceStats[i]->packageId == j)
            {
                tempPerformanceStats[k++] = data->performanceStats[i];
            }
        }
    }
    for (i = 0; i < data->numberOfThreads; i++)
    {
        data->performanceStats[i] = tempPerformanceStats[i];
    }
    memset(stats2, 0, sizeof(perf_data_t) * (packageIdCount_g + 1));
    /*point perf stats to clear structure*/
    setup->performanceStats = &stats;
    for (i = 0; i < (packageIdCount_g + 1); i++)
    {
        setup->performanceStats = &stats2[i];
        stats2[i].averagePacketSizeInBytes = data->packetSize;
        if (setup->performanceStats->averagePacketSizeInBytes == PACKET_IMIX)
        {
            stats2[i].averagePacketSizeInBytes = BUFFER_SIZE_1152;
        }
    }
    /*get our test bufferSize*/
    stats.averagePacketSizeInBytes = data->packetSize;
    thoughputSize = data->packetSize;
    if (data->packetSize == PACKET_IMIX)
    {
        thoughputSize = setup->performanceStats->averagePacketSizeInBytes;
    }
    /*get the lowest and highest cycle count from the list of threads (all the
     * same setup executed*/
    getLongestCycleCount2(stats2,
                          data->performanceStats,
                          data->numberOfThreads,
                          perfDataDeviceOffsets,
                          threadCountPerDevice);

    /*calc the total cycles of all threads (of one setup type) took to complete
     * and then print out the data*/
    for (i = 0; i < (packageIdCount_g + 1); i++)
    {
        accumulateSymPerfData(
            threadCountPerDevice[i],
            &(data->performanceStats[perfDataDeviceOffsets[i]]),
            &stats2[i],
            setup,
            &buffersProcessed,
            &responsesPerThread);

        numOfCycles =
            (stats2[i].endCyclesTimestamp - stats2[i].startCyclesTimestamp);
        if (!signOfLife)
        {
            devThoughput =
                getThroughput(buffersProcessed, thoughputSize, numOfCycles);
        }
        buffersProcessed = 0;
        throughput += devThoughput;
        stats.numOperations += stats2[i].numOperations;
        stats.responses += stats2[i].responses;
        stats.retries += stats2[i].retries;
        if (iaCycleCount_g)
        {
            stats.offloadCycles += stats2[i].offloadCycles;
        }
#ifdef LATENCY_CODE
        if (latency_enable)
        {
            stats.minLatency += stats2[i].minLatency;
            stats.aveLatency += stats2[i].aveLatency;
            stats.maxLatency += stats2[i].maxLatency;
        }
#endif
    }

    printSymTestType(setup);
    if (data->packetSize == PACKET_IMIX)
    {
        PRINT("Packet Mix\
        40%%-64B 20%%-752B 35%% 1504B 5%%-8892B\n");
    }
    else
    {
        PRINT("Packet Size           %u\n",
              setup->performanceStats->averagePacketSizeInBytes);
    }
    PRINT("Number of Threads     %u\n", data->numberOfThreads);
    PRINT("Total Submissions     %llu\n",
          (unsigned long long)stats.numOperations);
    PRINT("Total Responses       %llu\n", (unsigned long long)stats.responses);
    PRINT("Total Retries         %llu\n", (unsigned long long)stats.retries);
    if (!signOfLife)
    {
        PRINT("CPU Frequency(kHz)    %u\n", sampleCodeGetCpuFreq());
        if (responsesPerThread < THROUGHPUT_MIN_SUBMISSIONS)
        {
            PRINT("Need to submit >= %u per thread for accurate throughput\n",
                  THROUGHPUT_MIN_SUBMISSIONS);
        }
        else
        {
            PRINT("Throughput(Mbps)      %u\n", throughput);
        }


#ifdef LATENCY_CODE
        if (latency_enable)
        {
            perf_cycles_t statsLatency = 0;
            perf_cycles_t cpuFreqKHz = sampleCodeGetCpuFreq();

            /*Display how long it took on average to process a buffer in uSecs.
             *Also include min/max to show variance */
            do_div(stats.minLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.minLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Min. Latency (uSecs)     %llu\n", statsLatency);
            do_div(stats.aveLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.aveLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Ave. Latency (uSecs)     %llu\n", statsLatency);
            do_div(stats.maxLatency, data->numberOfThreads);
            statsLatency = 1000 * stats.maxLatency;
            do_div(statsLatency, cpuFreqKHz);
            PRINT("Max. Latency (uSecs)     %llu\n", statsLatency);
        }
#endif
        if (iaCycleCount_g)
        {
            do_div(stats.offloadCycles, data->numberOfThreads);
            PRINT("Avg Offload Cycles    %llu\n",
                  (long long unsigned int)stats.offloadCycles);
        }
    }
    qaeMemFree((void **)&stats2);
    qaeMemFree((void **)&perfDataDeviceOffsets);
    qaeMemFree((void **)&threadCountPerDevice);
    qaeMemFree((void **)&tempPerformanceStats);
    return CPA_STATUS_SUCCESS;
}

/**/
CpaStatus switchCipherDirection()
{
    PRINT("New cipher direction: ");
    if (cipherDirection_g == CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT)
    {
        PRINT("CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT\n");
        cipherDirection_g = CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
    }
    else
    {
        PRINT("CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT\n");
        cipherDirection_g = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    }
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(switchCipherDirection);

/*****************************************************************************
 * @ingroup sampleSymmetricDpPerf
 *
 * @description
 * Set the digestAppend flag to true or false
 * ***************************************************************************/
CpaStatus setDigestAppend(CpaBoolean flag)
{
    digestAppended_g = flag;
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(setDigestAppend);


void setBusyLoopMethod(Cpa32U method)
{
    busyLoopMethod_g = method;
    return;
}
EXPORT_SYMBOL(busyLoopMethod_g);
EXPORT_SYMBOL(setBusyLoopMethod);

void setTimeStampInLoop(CpaBoolean value)
{
    timeStampInLoop = value;
    return;
}
EXPORT_SYMBOL(timeStampInLoop);
EXPORT_SYMBOL(setTimeStampInLoop);

/************************************************************************
 *  * Name: checkCapability
 *   * Description: Checks whether the given logical instance supports
 *    *  cipherAlg/hashAlg
 *     * Return : True if supported, False, otherwise
 *      ************************************************************************/

CpaBoolean checkCapability(CpaInstanceHandle *cyInstanceHandle,
                           symmetric_test_params_t *symTestSetup)
{
    CpaCySymCapabilitiesInfo cySymCapInfo = {};
    CpaCySymCapabilitiesInfo *pCapInfo = NULL;

    if (!(symTestSetup->setupData.cipherSetupData.cipherAlgorithm |
          symTestSetup->setupData.hashSetupData.hashAlgorithm))
    {
        return CPA_FALSE;
    }
    if (CPA_STATUS_SUCCESS !=
        cpaCySymQueryCapabilities(cyInstanceHandle, &cySymCapInfo))
    {
        PRINT_ERR("cpaCySymQueryCapabilities fail\n");
        return CPA_FALSE;
    }
    pCapInfo = &cySymCapInfo;
    switch (symTestSetup->setupData.symOperation)
    {
        case CPA_CY_SYM_OP_CIPHER:
            if (symTestSetup->setupData.cipherSetupData.cipherAlgorithm &&
                ((CPA_BITMAP_BIT_TEST(pCapInfo->ciphers,
                                      symTestSetup->setupData.cipherSetupData
                                          .cipherAlgorithm)) == CPA_FALSE))
            {
                PRINT("\nUn supported Cipher ");
                printCipherAlg(symTestSetup->setupData.cipherSetupData);
                return CPA_FALSE;
            }
            break;
        case CPA_CY_SYM_OP_HASH:
            if (symTestSetup->setupData.hashSetupData.hashAlgorithm &&
                ((CPA_BITMAP_BIT_TEST(
                     pCapInfo->hashes,
                     symTestSetup->setupData.hashSetupData.hashAlgorithm)) ==
                 CPA_FALSE))
            {
                PRINT("\nUn supported Hash ");
                printHashAlg(symTestSetup->setupData.hashSetupData);
                return CPA_FALSE;
            }
            break;
        case CPA_CY_SYM_OP_ALGORITHM_CHAINING:
            if (symTestSetup->setupData.cipherSetupData.cipherAlgorithm &&
                ((CPA_BITMAP_BIT_TEST(pCapInfo->ciphers,
                                      symTestSetup->setupData.cipherSetupData
                                          .cipherAlgorithm)) == CPA_FALSE))
            {
                PRINT("\nUn supported AlgChain ");
                printCipherAlg(symTestSetup->setupData.cipherSetupData);
                return CPA_FALSE;
            }
            if (symTestSetup->setupData.hashSetupData.hashAlgorithm &&
                ((CPA_BITMAP_BIT_TEST(
                     pCapInfo->hashes,
                     symTestSetup->setupData.hashSetupData.hashAlgorithm)) ==
                 CPA_FALSE))
            {
                PRINT("\nUn supported AlgChain ");
                printHashAlg(symTestSetup->setupData.hashSetupData);
                return CPA_FALSE;
            }
            break;
        default:
            PRINT_ERR("\nUn supported Sym operation: %d\n",
                      symTestSetup->setupData.symOperation);
            return CPA_FALSE;
    }
    return CPA_TRUE;
}
EXPORT_SYMBOL(checkCapability);
EXPORT_SYMBOL(setCyPollWaitFn);
CpaStatus getCyInstanceCapabilities(CpaCyCapabilitiesInfo *pCap)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    status = cpaCyGetInstances(1, &instanceHandle);
    if (instanceHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCyQueryCapabilities(instanceHandle, pCap);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(getCyInstanceCapabilities);

CpaStatus getCryptoInstanceCapabilities(CpaCyCapabilitiesInfo *cap,
                                        Cpa32U instType)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa16U nSymInstances = 0;
    Cpa16U nAsymInstances = 0;

#if CY_API_VERSION_AT_LEAST(3, 0)
    cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, &nSymInstances);
    cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_ASYM, &nAsymInstances);
#endif

    /* Sym/Asym Instances will be 0 for 1.x platforms.
     * Return the first Crypto Instance Capabilities
     */
    if (nSymInstances == 0 && nAsymInstances == 0)
    {
        status = getCyInstanceCapabilities(cap);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("getCyInstanceCapabilities failed with status: %d\n",
                      status);
        }
        return status;
    }

#if CY_API_VERSION_AT_LEAST(3, 0)
    if (SYM == instType && nSymInstances > 0)
    {
        status = getSymAsymInstanceCapabilities(cap, instType);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("getSymAsymInstanceCapabilities failed with status: %d\n",
                      status);
            return status;
        }
    }
    if (ASYM == instType && nAsymInstances > 0)
    {
        status = getSymAsymInstanceCapabilities(cap, instType);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("getSymAsymInstanceCapabilities failed with status: %d\n",
                      status);
            return status;
        }
        return CPA_STATUS_SUCCESS;
    }
#endif
    return status;
}
EXPORT_SYMBOL(getCryptoInstanceCapabilities);

#if CY_API_VERSION_AT_LEAST(3, 0)
CpaStatus getSymAsymInstanceCapabilities(CpaCyCapabilitiesInfo *pCap,
                                         Cpa32U instType)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;

    if (SYM == instType)
    {
        status =
            cpaGetInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, 1, &instanceHandle);
    }
    else
    {
        status =
            cpaGetInstances(CPA_ACC_SVC_TYPE_CRYPTO_ASYM, 1, &instanceHandle);
    }

    if (instanceHandle == NULL)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    status = cpaCyQueryCapabilities(instanceHandle, pCap);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(getSymAsymInstanceCapabilities);
#endif

CpaStatus getCySymQueryCapabilities(CpaCySymCapabilitiesInfo *pCap)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
    Cpa16U nSymInstances = 0;

#if CY_API_VERSION_AT_LEAST(3, 0)
    cpaGetNumInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, &nSymInstances);
    if (nSymInstances > 0)
    {
        cpaGetInstances(CPA_ACC_SVC_TYPE_CRYPTO_SYM, 1, &instanceHandle);
    }
#endif

    /* Sym Instance will be 0 for 1.x platforms. */
    if (nSymInstances == 0)
    {
        status = cpaCyGetInstances(1, &instanceHandle);
    }

    if (instanceHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCySymQueryCapabilities(instanceHandle, pCap);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(getCySymQueryCapabilities);

CpaStatus getCySpecificInstanceCapabilities(CpaInstanceHandle instanceHandle,
                                            CpaCyCapabilitiesInfo *pCap)
{
    CpaStatus status = CPA_STATUS_FAIL;

    if (instanceHandle == NULL)
    {
        return CPA_STATUS_FAIL;
    }

    status = cpaCyQueryCapabilities(instanceHandle, pCap);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(getCySpecificInstanceCapabilities);

/*
 * The setupSymmetricDpTest() function has the encrypt / decrypt
 * direction hard coded to CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT.
 * Use setCipherDirection() before calling setupCipherDpTest().
 */
CpaCySymCipherDirection getCipherDirection(void)
{
    return cipherDirection_g;
}
EXPORT_SYMBOL(getCipherDirection);

/*
 * The setupSymmetricDpTest() function has the encrypt / decrypt
 * direction hard coded to CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT.
 * Use setCipherDirection() before calling setupCipherDpTest().
 */
void setCipherDirection(CpaCySymCipherDirection direction)
{
    switch (direction)
    {
        case CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT:
            PRINT("%s: cipherDirection_g is now ENCRYPT\n", __FUNCTION__);
            cipherDirection_g = direction;
            break;

        case CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT:
            PRINT("%s: cipherDirection_g is now DECRYPT\n", __FUNCTION__);
            cipherDirection_g = direction;
            break;

        default:
            PRINT("ERROR: %s: setCipherDirection( %d ) invalid argument\n",
                  __FUNCTION__,
                  (int)direction);
            break;
    }
}
EXPORT_SYMBOL(setCipherDirection);


CpaStatus sampleCodeAsymPollInstance(CpaInstanceHandle instanceHandle_in,
                                     Cpa32U response_quota)
{
    {
        return icp_sal_CyPollInstance(instanceHandle_in, response_quota);
    }
}

CpaStatus sampleCodeSymPollInstance(CpaInstanceHandle instanceHandle_in,
                                    Cpa32U response_quota)
{
    {
        return icp_sal_CyPollInstance(instanceHandle_in, response_quota);
    }
}

CpaStatus checkForChachapolySupport(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCySymCapabilitiesInfo capInfo = {{0}};
    Cpa16U numCyInstances = 0;
    Cpa16U i = 0;
    CpaInstanceHandle *cyInstances = NULL;

    /*Get number of Crypto Instances*/
    status = cpaCyGetNumInstances(&numCyInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
        return status;
    }
    if (0 == numCyInstances)
    {
        PRINT_ERR("There are no Crypto Instances avaialble!\n");
        return CPA_STATUS_FAIL;
    }
    cyInstances = qaeMemAlloc(sizeof(CpaInstanceHandle) * numCyInstances);
    if (NULL == cyInstances)
    {
        PRINT_ERR("Failed to allocate memory for instances\n");
        return CPA_STATUS_FAIL;
    }
    status = cpaCyGetInstances(numCyInstances, cyInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
        qaeMemFree((void **)&cyInstances);
        return status;
    }
    /*Check for required Capability in all instances. Set the Success Status
     *if required capability is supported in any instance.
     */
    status = CPA_STATUS_FAIL;
    for (i = 0; i < numCyInstances; i++)
    {
        if (CPA_STATUS_SUCCESS ==
            cpaCySymQueryCapabilities(cyInstances[i], &capInfo))
        {
            if (CPA_BITMAP_BIT_TEST(capInfo.ciphers, CPA_CY_SYM_CIPHER_CHACHA))
            {
                status = CPA_STATUS_SUCCESS;
                break;
            }
        }
    }
    if (NULL != cyInstances)
    {
        qaeMemFree((void **)&cyInstances);
    }
    return status;
}
