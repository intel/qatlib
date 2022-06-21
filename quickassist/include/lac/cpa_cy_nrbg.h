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

/*
 *****************************************************************************
 * Doxygen group definitions
 ****************************************************************************/

/**
 *****************************************************************************
 * @file cpa_cy_nrbg.h
 *
 * @defgroup cpaCyNrbg Non-Deterministic Random Bit Generation API
 *
 * @ingroup cpaCy
 *
 * @description
 *      These functions specify the API for Non-Deterministic Random Bit
 *      Generation (NRBG).  This is used to provide entropy to a
 *      Deterministic RBG (DRBG).
 *
 * @note
 *         These functions supersede the random number generation functions
 *      in API group @ref cpaCyRand, which are now deprecated.
 *
 *****************************************************************************/

#ifndef CPA_CY_NRBG_H
#define CPA_CY_NRBG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cpa_cy_common.h"


/**
 *****************************************************************************
 * @ingroup cpaCyNrbg
 *      NRBG Get Entropy Operation Data
 * @description
 *      This structure contains data relating to generation of entropy
 *      using an NRBG.
 * @see
 *         cpaCyNrbgGetEntropy()
 * @note
 *      If the client modifies or frees the memory referenced in this structure
 *      after it has been submitted to the @ref cpaCyNrbgGetEntropy() function,
 *      and before it has been returned in the callback, undefined behavior will
 *      result.
 *****************************************************************************/
typedef struct _CpaCyNrbgOpData {
    Cpa32U lengthInBytes;
    /**< Requested number of bytes to be generated.  On calls to @ref
     * cpaCyNrbgGetEntropy, this value must be greater than zero (>0).
     */
} CpaCyNrbgOpData;

/**
 *****************************************************************************
 * @ingroup cpaCyNrbg
 *      Gets entropy from the NRBG.
 *
 * @description
 *      This function returns a string of bits of specified length.
 *
 * @context
 *      When called as an asynchronous function it cannot sleep. It can be
 *      executed in a context that does not permit sleeping.
 *      When called as a synchronous function it may sleep. It MUST NOT be
 *      executed in a context that DOES NOT permit sleeping.
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @blocking
 *      Yes when configured to operate in synchronous mode.
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @param[in]  instanceHandle        Instance handle.
 * @param[in]  pCb                     Pointer to callback function to be invoked
 *                                   when the operation is complete. If this is
 *                                   set to a NULL value the function will operate
 *                                   synchronously.
 * @param[in]  pCallbackTag          Opaque User Data for this specific call. Will
 *                                   be returned unchanged in the callback.
 * @param[in]  pOpData                Structure containing all the data needed to
 *                                   perform the operation.
 *                                  The client code allocates the memory for this
 *                                   structure. This component takes ownership of
 *                                   the memory until it is returned in the
 *                                   callback.
 * @param[out] pEntropy                Pointer to memory allocated by the client
 *                                   to which the entropy will be written. For
 *                                   optimal performance, the data pointed to SHOULD
 *                                   be 8-byte aligned. There is no endianness
 *                                   associated with the entropy.
 *                                   On invocation the callback function will
 *                                   contain this parameter in its pOut parameter.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 * @pre
 *      The component has been initialized via the @ref cpaCyStartInstance
 *      function.
 * @post
 *      None
 * @note
 *      When pCb is non-NULL an asynchronous callback of type @ref
 *      CpaCyGenFlatBufCbFunc is generated in response to this function call.
 *      Any errors generated during processing are reported as part of the
 *      callback status code. For optimal performance, data pointers SHOULD be
 *      8-byte aligned.
 *****************************************************************************/
CpaStatus
cpaCyNrbgGetEntropy(const CpaInstanceHandle instanceHandle,
        const CpaCyGenFlatBufCbFunc pCb,
        void *pCallbackTag,
        const CpaCyNrbgOpData *pOpData,
        CpaFlatBuffer *pEntropy);

#ifdef __cplusplus
} /* close the extern "C" { */
#endif

#endif /* CPA_CY_NRBG_H */
