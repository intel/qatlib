/****************************************************************************
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
#ifndef QAT_PERF_UTILS_H_
#define QAT_PERF_UTILS_H_

#include "cpa.h"
#include "cpa_sample_code_utils_common.h"
#include "icp_sal_user.h"
#include "icp_sal_versions.h"
#include "cpa_cy_im.h"

/*set status to fail if the ptr is null*/
#define QAT_PERF_CHECK_NULL_POINTER_AND_UPDATE_STATUS(ptr, status)             \
    do                                                                         \
    {                                                                          \
        if (NULL == ptr)                                                       \
        {                                                                      \
            PRINT_ERR("NULL ptr passed %s\n", #ptr);                           \
            status = CPA_STATUS_FAIL;                                          \
        }                                                                      \
    } while (0)

/*free memory of a pointer, set status to fail if the pointer
 * is no null after calling free*/
#define QAT_PERF_FREE_MEM_AND_UPDATE_STATUS(ptr, status)                       \
    do                                                                         \
    {                                                                          \
        if (NULL != ptr)                                                       \
        {                                                                      \
            qaeMemFree((void **)&ptr);                                         \
            if (NULL != ptr)                                                   \
            {                                                                  \
                PRINT_ERR("Could not free memory\n");                          \
                status = CPA_STATUS_FAIL;                                      \
            }                                                                  \
        }                                                                      \
    } while (0)

/*print function, line number and fail return code*/
#define QAT_PERF_PRINT_ERR_FOR_NON_SUCCESS_STATUS(str, status)                 \
    do                                                                         \
    {                                                                          \
        if (CPA_STATUS_SUCCESS != status)                                      \
        {                                                                      \
            PRINT_ERR("%s error: status:%d\n", str, status);                   \
        }                                                                      \
    } while (0)

/*goto label if the ptr is null*/
#define QAT_PERF_CHECK_NULL_POINTER_AND_GOTO_LABEL(ptr, label)                 \
    do                                                                         \
    {                                                                          \
        if (NULL == ptr)                                                       \
        {                                                                      \
            PRINT_ERR("NULL ptr passed %s\n", #ptr);                           \
            goto label;                                                        \
        }                                                                      \
    } while (0)
/*goto label if the parameter range is invalid */
#define QAT_PERF_CHECK_PARAM_RANGE_AND_GOTO_LABEL(param, min, max, label)      \
    do                                                                         \
    {                                                                          \
        if (((param) < (min)) || ((param) >= (max)))                           \
        {                                                                      \
            PRINT_ERR("Invalid File size: %d\n", param);                       \
            goto label;                                                        \
        }                                                                      \
    } while (0)

/*fail the test if something wrong before the sampleCodeBarrier and goto label*/
#define QAT_PERF_FAIL_WAIT_AND_GOTO_LABEL(setup, label)                        \
    do                                                                         \
    {                                                                          \
        setup->performanceStats->threadReturnStatus = CPA_STATUS_FAIL;         \
        sampleCodeBarrier();                                                   \
        goto label;                                                            \
    } while (0)

/*define a back off mechanism to stop performance operations constantly using
 * up 100% CPU.*/
#if defined(KERNEL_SPACE)
/*set a context switch to allow OS re-schedule thread, it also allows other
 *threads CPU time on the same core*/
/*note the soft lockup can be compiled out of the kernel, if that is the case
 * this step is not needed*/
#define AVOID_SOFTLOCKUP                                                       \
                                                                               \
    do                                                                         \
    {                                                                          \
        yield();                                                               \
                                                                               \
    } while (0)
#ifndef AVOID_SOFTLOCKUP_POLL
#define AVOID_SOFTLOCKUP_POLL AVOID_SOFTLOCKUP
#endif
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

typedef enum sync_mode_s
{
    SYNC = 0,
    ASYNC
} sync_mode_t;

/**
 *****************************************************************************
 * @file qat_perf_utils.h
 *
 * @ingroup sample_code
 *
 * @description Initialize a sample_code perf_data_t structure
 *
 * @param[in]   performanceStats      ptr to perfStats to be initialized
 *
 * @param[in]   numLists              number of CpaBufferLists being used in
 *                                    test
 * @param[in]   numLoops              number to resubmit numLists
 *
 * @param[in]   pollingInterval       how many request to be made for inline
 *                                    polling mode before a poll for responses
 *                                    is done
 *
 * @pre                               perfStats already allocated
 *
 * @post                              zero out perfStats structure, then set
 *                                    perfStats->numLoops and
 *                                    perfStats->numOperations =
 *                                                      numLoops * numLists
 *
 * @retval none
 *****************************************************************************/
void qatPerfInitStats(perf_data_t *performanceStats,
                      Cpa32U numLists,
                      Cpa32U numLoops,
                      Cpa32U pollingInterval);

/**
 *****************************************************************************
 * @file qat_perf_utils.h
 * *
 * @ingroup sample_code
 *
 * @description Converts a CpaStatus return code to its readable string code
 *
 * @param[in]   status                CpaStatus code to be converted
 *
 * @retval human readable string of the equivalent status code
 *****************************************************************************/
char *cpaStatusToString(CpaStatus status);

/**
 *****************************************************************************
 * @file qat_perf_utils.h
 * *
 * @ingroup sample_code
 *
 * @description Copy data from src buffer to dst buffer
 *
 * @param[in]   srcBufferListArray      pointer to data to be copied
 * @param[in]   dstBufferListArray      pointer to where data is to be copied
 *
 *
 * @retval human readable string of the equivalent status code
 *****************************************************************************/
CpaStatus copyBuffers(CpaBufferList *srcBufferListArray,
                      CpaBufferList *copyBufferListArray,
                      Cpa32U numberOfLists);

/**
 *****************************************************************************
 * @file qat_perf_utils.h
 * *
 * @ingroup sample_code
 *
 * @description Print QAT driversion
 *
 * @param[in]   deviceNum      device Number
 *
 *
 * @retval human readable string of the equivalent status code
 *****************************************************************************/
CpaStatus printDriverVersion(Cpa32U deviceNum);

#endif /* QAT_PERF_UTILS_H_ */
