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

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description
*     This file contains inline functions used to measure cost of offload
*
*****************************************************************************/
#ifndef __QAT_PERF_CYCLES_H_
#define __QAT_PERF_CYCLES_H_

#include "icp_sal_poll.h"

/* Global state of initialization */
static Cpa8U coo_initialized = CPA_FALSE;

/* This is used to define a pointer to a function */
typedef CpaStatus (*coo_poll_func)(CpaInstanceHandle, Cpa32U);

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function is used to init coo values
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   size                number of operations used to allocate
*                                  memory for coo values
*
* @retval CPA_STATUS_SUCCESS       Coo is initialized and all memory was
*                                  allocated
*
* @retval CPA_STATUS_FAIL          Coo is not initialized and memory is freed
*                                  before return of function
*
****************************************************************************/
static inline void coo_init(perf_data_t *perf_data, Cpa64U size)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g)
    {
        perf_data->req_temp = 0;
        perf_data->cost_temp = 0;
        perf_data->req_count = 0;
        perf_data->req_cost_count = 0;
        perf_data->poll_cost_count = 0;
        perf_data->req_sum_cycles = 0;
        perf_data->req_cost_sum_cycles = 0;
        perf_data->poll_sum_cycles = 0;
        perf_data->poll_cost_sum_cycles = 0;
        coo_initialized = CPA_TRUE;
    }
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function is used reset coo values
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
****************************************************************************/
static inline void coo_deinit(perf_data_t *perf_data)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g)
    {
        perf_data->req_temp = 0;
        perf_data->cost_temp = 0;
        perf_data->req_count = 0;
        perf_data->req_cost_count = 0;
        perf_data->poll_cost_count = 0;
        perf_data->req_sum_cycles = 0;
        perf_data->req_cost_sum_cycles = 0;
        perf_data->poll_sum_cycles = 0;
        perf_data->poll_cost_sum_cycles = 0;
        coo_initialized = CPA_FALSE;
    }
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function is used to retrieve timestamp
*
* @retval      perf_cycles_t       time stamp value
*
****************************************************************************/
static inline perf_cycles_t coo_timestamp(void)
{
#ifdef __x86_64__
    uint32_t cycles_high;
    uint32_t cycles_low;

    __asm__ volatile(
        "rdtscp\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");

    return (((perf_cycles_t)cycles_high << 32) | cycles_low);
#else
    Cpa64U ts = 0;
    asm volatile("rdtsc" : "=A"(ts));
    return ((perf_cycles_t)ts);
#endif
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function is used to retrieve time stamp
*                                  before sending request
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
****************************************************************************/
static inline void coo_req_start(perf_data_t *perf_data)
{
    /* Start coo measure */
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
        perf_data->req_temp = coo_timestamp();
}
/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     This function takes a timestamp after
*                                  sending a request. The difference of start
*                                  and pause is stored in a sum in perf_data.
*                                  If request status is not equal to
*                                  CPA_STATUS_SUCCESS request coo value will
*                                  not be added to the sum. This call is used
*                                  to measure coo of several requests. The
*                                  value of req_count is not incremented.
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   status              request status
*
****************************************************************************/
static inline void coo_req_pause(perf_data_t *perf_data, CpaStatus status)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
    {
        perf_cycles_t stop_timestamp = coo_timestamp();
        /* End coo measure */

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Temporary sum used in overwrap check */
            perf_cycles_t req_sum_temp = 0;
            perf_cycles_t cost_sum_temp = 0;

            /* Start coo cost measure */
            perf_data->cost_temp = coo_timestamp();

            /* Simulate call function coo_req_pause() */
            if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
            {
                perf_cycles_t cost_timestamp = coo_timestamp();
                /* End coo cost measure */

                /* Store coo cost value into cost_sum_temp and check for
                 * overwrap */
                cost_sum_temp = perf_data->req_cost_sum_cycles +
                                (cost_timestamp - perf_data->cost_temp);
                if (cost_sum_temp < perf_data->req_cost_sum_cycles)
                    PRINT_ERR("req_cost_sum_cycles overwrap!\n");
                else
                    perf_data->req_cost_sum_cycles = cost_sum_temp;
            }
            /* Calculate req coo value */
            req_sum_temp = perf_data->req_sum_cycles +
                           (stop_timestamp - perf_data->req_temp);

            /* Check for req sum overwrap */
            if (req_sum_temp < perf_data->req_sum_cycles)
                PRINT_ERR("req_sum_cycles overwrap!\n");
            else
                perf_data->req_sum_cycles = req_sum_temp;

            /* Reset temporary values */
            perf_data->req_temp = 0;
            perf_data->cost_temp = 0;
        }
        else
            /* Reset request temporary value */
            perf_data->req_temp = 0;
    }
}
/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     This function takes a timestamp after
*                                  sending the request. The Difference
*                                  between start and pause is stored as sum in
*                                  perf_data. If request status is not equal to
*                                  CPA_STATUS_SUCCESS request coo value will
*                                  not be added to the sum. When measuring coo
*                                  of several requests, this function should
*                                  be called at the end of last measured
*                                  function in loop.
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   status              request status
*
****************************************************************************/
static inline void coo_req_stop(perf_data_t *perf_data, CpaStatus status)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
    {
        perf_cycles_t stop_timestamp = coo_timestamp();
        /* End coo measure */

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Temporary sum used in overwrap check */
            perf_cycles_t req_sum_temp = 0;
            perf_cycles_t cost_sum_temp = 0;

            /* Start coo cost measure */
            perf_data->cost_temp = coo_timestamp();

            /* Simulate call function coo_req_stop() */
            if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
            {
                perf_cycles_t cost_timestamp = coo_timestamp();
                /* End coo cost measure */

                /* Store coo cost value into cost_sum_temp and check for
                 * overwrap */
                cost_sum_temp = perf_data->req_cost_sum_cycles +
                                (cost_timestamp - perf_data->cost_temp);
                if (cost_sum_temp < perf_data->req_cost_sum_cycles)
                    PRINT_ERR("req_cost_sum_cycles overwrap!\n");
                else
                {
                    perf_data->req_cost_sum_cycles = cost_sum_temp;
                    perf_data->req_cost_count++;
                }
            }
            /* Calculate req coo value */
            req_sum_temp = perf_data->req_sum_cycles +
                           (stop_timestamp - perf_data->req_temp);

            /* Check for req sum overwrap */
            if (req_sum_temp < perf_data->req_sum_cycles)
                PRINT_ERR("req_sum_cycles overwrap!\n");
            else
            {
                perf_data->req_sum_cycles = req_sum_temp;
                perf_data->req_count++;
            }

            /* Reset temporary values */
            perf_data->req_temp = 0;
            perf_data->cost_temp = 0;
        }
        else
            /* Reset request temporary value */
            perf_data->req_temp = 0;
    }
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function performs polling on instance
*                                  and measures coo of polling. If polling
*                                  status is equal to CPA_STATUS_SUCCESS
*                                  poll value will be added to sum in perf
*                                  data.
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   func                pointer to function used to perform polling
*
* @param[in]   instance            instance handle used in polling function
*
* @param[in]   status              pointer to status where polling function
*                                  will return value
*
****************************************************************************/
static inline void coo_poll(perf_data_t *perf_data,
                            coo_poll_func func,
                            CpaInstanceHandle instance,
                            CpaStatus *status)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
    {
        /* Initialize local variables */
        perf_cycles_t poll_start_timestamp = 0;
        perf_cycles_t poll_stop_timestamp = 0;

        /* Start coo measure */
        poll_start_timestamp = coo_timestamp();
        *status = func(instance, 0);
        poll_stop_timestamp = coo_timestamp();
        /* End coo measure */

        if (CPA_STATUS_SUCCESS == *status)
        {
            /* Initialize local variables */
            perf_cycles_t cost_start_timestamp = 0;
            perf_cycles_t cost_stop_timestamp = 0;
            perf_cycles_t poll_sum_temp = 0;
            perf_cycles_t cost_sum_temp = 0;

            /* Start coo cost measure */
            cost_start_timestamp = coo_timestamp();
            cost_stop_timestamp = coo_timestamp();
            /* End coo cost measure */

            cost_sum_temp = perf_data->poll_cost_sum_cycles +
                            (cost_stop_timestamp - cost_start_timestamp);
            if (cost_sum_temp < perf_data->poll_cost_sum_cycles)
                PRINT_ERR("poll_cost_sum_cycles overwrap!\n");
            else
            {
                perf_data->poll_cost_sum_cycles = cost_sum_temp;
                perf_data->poll_cost_count++;
            }

            /* Add poll cycles value to poll_sum_temp */
            poll_sum_temp = perf_data->poll_sum_cycles +
                            (poll_stop_timestamp - poll_start_timestamp);

            /* Check for poll sum overwrap */
            if (poll_sum_temp < perf_data->poll_sum_cycles)
                PRINT_ERR("poll_sum_cycles overwrap!\n");
            else
                perf_data->poll_sum_cycles = poll_sum_temp;
        }
    }
    else
        *status = func(instance, 0);
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function id used to call coo_poll using
*                                  polling function in traditional mode for
*                                  crypto instances
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   instance            instance handle used in polling function
*
* @param[in]   status              pointer to status where polling function
*                                  will return value
*
****************************************************************************/
static inline void coo_poll_trad_cy(perf_data_t *perf_data,
                                    CpaInstanceHandle instance,
                                    CpaStatus *status)
{
    coo_poll(perf_data, icp_sal_CyPollInstance, instance, status);
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function id used to call coo_poll using
*                                  polling function in traditional mode for
*                                  compression instances
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   instance            instance handle used in polling function
*
* @param[in]   status              pointer to status where polling function
*                                  will return value
*
****************************************************************************/
static inline void coo_poll_trad_dc(perf_data_t *perf_data,
                                    CpaInstanceHandle instance,
                                    CpaStatus *status)
{
    coo_poll(perf_data, icp_sal_DcPollInstance, instance, status);
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function id used to call coo_poll using
*                                  polling function in data plane mode for
*                                  crypto instances
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   instance            instance handle used in polling function
*
* @param[in]   status              pointer to status where polling function
*                                  will return value
*
****************************************************************************/
static inline void coo_poll_dp_cy(perf_data_t *perf_data,
                                  CpaInstanceHandle instance,
                                  CpaStatus *status)
{
    coo_poll(perf_data, icp_sal_CyPollDpInstance, instance, status);
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function id used to call coo_poll using
*                                  polling function in data plane mode for
*                                  compression instances
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @param[in]   instance            instance handle used in polling function
*
* @param[in]   status              pointer to status where polling function
*                                  will return value
*
****************************************************************************/
static inline void coo_poll_dp_dc(perf_data_t *perf_data,
                                  CpaInstanceHandle instance,
                                  CpaStatus *status)
{
    coo_poll(perf_data, icp_sal_DcPollDpInstance, instance, status);
}

/**
*****************************************************************************
* @file qat_perf_cycles.h
*
* @ingroup sample_code
*
* @description                     Function performs average cost of offload
*                                  calculation using coo data stored in
*                                  perf_data
*
* @param[in]   perf_data           pointer to structure of performance data
*                                  used to store cyclecount values
*
* @retval CPA_STATUS_SUCCESS       Cost of offload is calculated
* @retval CPA_STATUS_FAIL          Cost of offload is not calculated
*
****************************************************************************/
static inline void coo_average(perf_data_t *perf_data)
{
    if (CPA_CC_REQ_POLL_STAMP == iaCycleCount_g && coo_initialized)
    {
        /* Init local variables */
        perf_cycles_t avg_req_cycles = 0;
        perf_cycles_t avg_req_cost_cycles = 0;
        perf_cycles_t avg_poll_cycles = 0;
        perf_cycles_t avg_poll_cost_cycles = 0;
        perf_cycles_t req_count = perf_data->req_count;
        perf_cycles_t req_cost_count = perf_data->req_cost_count;
        perf_cycles_t poll_cost_count = perf_data->poll_cost_count;
        perf_cycles_t req_sum_cycles = perf_data->req_sum_cycles;
        perf_cycles_t req_cost_sum_cycles = perf_data->req_cost_sum_cycles;
        perf_cycles_t poll_sum_cycles = perf_data->poll_sum_cycles;
        perf_cycles_t poll_cost_sum_cycles = perf_data->poll_cost_sum_cycles;

        /* Calculate average values */
        if ((req_sum_cycles > 0) && (req_count > 0))
            avg_req_cycles = req_sum_cycles / req_count;

        if ((req_cost_sum_cycles > 0) && (req_cost_count > 0))
            avg_req_cost_cycles = req_cost_sum_cycles / req_cost_count;

        if ((poll_sum_cycles > 0) && (req_count > 0))
            avg_poll_cycles = poll_sum_cycles / req_count;

        if ((poll_cost_sum_cycles > 0) && (poll_cost_count > 0))
            avg_poll_cost_cycles = poll_cost_sum_cycles / poll_cost_count;

        /* Calculate coo value and store in perf data */
        perf_data->offloadCycles = (avg_req_cycles - avg_req_cost_cycles) +
                                   (avg_poll_cycles - avg_poll_cost_cycles);
    }
}
#endif /* __QAT_PERF_CYCLES_H_ */
