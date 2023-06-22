/******************************************************************************
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
 *****************************************************************************/
/**************************************************************************
 * @file lac_ln.h
 *
 * @defgroup LacAsymLn     Large Number ModExp and ModInv
 *
 * @ingroup LacAsym
 *
 * Interfaces exposed by the LN Component
 *
 * @lld_start
 *
 * @lld_overview
 * This is the Large Number ModExp and ModInv feature implementation. It
 * implements two LN services: Modular Exponentiation and Modular Inversion.
 *
 * The input data size for each service can be any up to 4096 bits in length.
 * For each service the parameters supplied by the client are checked and then
 * the QAT functionality is chosen based upon input data size (buffer size less
 * leading zeros). In addition, the Modular Inversion service checks on the
 * even/odd combinations of the input data before choosing the flavour of the
 * QAT function.
 *
 * Finally the input/output argument lists are constructed before calling the PKE
 * QAT Comms layer to create and send a request to the QAT.
 *
 * Buffer alignment, and padding up to a chosen size (whole number of quadwords
 * matching the size of functionality ID) is handled by the PKE QAT Comms layer.
 *
 * Statistics are maintained for each service.
 *
 * @note
 * This feature may be called in Asynchronous or Synchronous modes.
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
 * @lld_dependencies
 * - @ref LacPkeQatComms "PKE QAT Comms" : For creating and sending messages
 * to the QAT
 * - @ref LacMem "Mem" : For memory allocation and freeing, and translating
 * between scalar and pointer types
 * - OSAL : For atomics and logging
 *
 * @lld_initialisation
 * On initialization this component clears the stats.
 *
 * @lld_module_algorithms
 *
 * @lld_process_context
 *
 * @lld_end
 *
 ***************************************************************************/

/*****************************************************************************/

#ifndef LAC_LN_H
#define LAC_LN_H

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

/**
 *******************************************************************************
 * @ingroup LacAsymLn
 *      print the LN stats to standard output
 *
 * @description
 *      For each Instance this function copies the stats using the function
 *      cpaCyLnStatsQuery64. It then prints contents of this structure to
 *      standard output
 *
 * @param[in] instanceHandle
 *
 * @see cpaCyLnStatsQuery64()
 *
 *****************************************************************************/
void LacLn_StatsShow(CpaInstanceHandle instanceHandle);

/**
 *******************************************************************************
 * @ingroup Lac_Ln
 *      Compile time check of FW interface
 *
 * @description
 *      Performs a compile time check of PKE interface to ensure IA assumptions
 *      about the interface are valid.
 *
 *****************************************************************************/
void LacLn_CompileTimeAssertions(void);

#endif /* LAC_LN_H */
