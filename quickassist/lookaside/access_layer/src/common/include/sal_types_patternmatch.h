/***************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 * 
 *   GPL LICENSE SUMMARY
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
#ifndef LAC_SAL_TYPES_PATTERNMATCH_H_
#define LAC_SAL_TYPES_PATTERNMATCH_H_

/**
 *****************************************************************************
 * @ingroup SalCtrl
 *      PatternMatch specific Service Container
 *
 * @description
 *      Contains information required per pattern match service instance.
 *
 *****************************************************************************/
typedef struct sal_patternmatch_service_s
{
    sal_service_t generic_service_info;
    /**< An instance of the Generic Service Container */

    lac_memory_pool_id_t patternmatch_mem_pool;
    /**< Memory pool ID used for patternmatch */

    OsalAtomic *pPmStatsArr;
    /**< Pointer to an array of atomic stats (Cpa64U) for pattern_match */

    icp_comms_trans_handle trans_handle_patternmatch_tx;

    icp_comms_trans_handle trans_handle_patternmatch_rx;
    Cpa32U pmResponseRingId;

    /* pointers to head and tail of list of matchContexts returned if the
     * callback is set to NULL for the matchContext, this builds a list of
     * results and is cleared by calling function cpaPmPollResults.
     */
    CpaPmMatchCtx *pPolledMatchCtxListHead;
    CpaPmMatchCtx *pPolledMatchCtxListTail;

    /* Resources for handling the polled list:
     * List lock for granting/revoking access to the list (while list is
     * being updated.
     * Semaphore is posted if cpaPmPollResults is blocking (set to true). If it
     * is blocking and the polled list is empty, it waits until a polled match
     * is added to the list.
     * Boolean isWaiting used for controlling the semaphore (it is a check to
     * see if cpaPmPollResults is blocking and if true, the semaphore is posted)
     */
    lac_lock_t pPolledMatchCtxListLock;
    OsalSemaphore sid;
    CpaBoolean isWaiting;

    lac_lock_t activePDBLock;
    /* pointer to the currently active database for this instance */
    pm_pdb_desc_t *pActiveDB;

    /* Config info */
    Cpa16U acceleratorNum;
    Cpa16U bankNum;
    Cpa16U pkgID;
    Cpa16U isPolled;
    Cpa32U coreAffinity;
    Cpa32U nodeAffinity;
    /* Statistics handler */
    debug_file_info_t *debug_file;
} sal_patternmatch_service_t;

/*************************************************************************
 * @ingroup SalCtrl
 * @description
 *  This function returns a valid patternmatch instance handle for the system
 *  if it exists.
 *
 *  @performance
 *    To avoid calling this function the user of the QA api should not use
 *    instanceHandle = CPA_INSTANCE_HANDLE_SINGLE.
 *
 * @context
 *    This function is called whenever instanceHandle =
 *                                                  CPA_INSTANCE_HANDLE_SINGLE
 *    at the QA Patternmatch api.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      No
 * @threadSafe
 *      Yes
 *
 * @retval   Pointer to first patternmatch instance handle or NULL if no
 *           patternmatch instances in the system.
 *
 *************************************************************************/
CpaInstanceHandle Pm_GetFirstHandle(void);

/******************************************************************************
 * Pattern match quick assist helper function implementations
 ******************************************************************************/

void PmPdb_CrcTableInit(Cpa32U *pCrcTable);

#endif /* LAC_SAL_TYPES_PATTERNMATCH_H_ */
