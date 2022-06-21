/*****************************************************************************
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

/*****************************************************************************
 * @file adf_ETring_mgr_dp.c
 *
 * @description
 *      ET Ring Manager for data plane
 *
 *****************************************************************************/

#include "cpa.h"
#include "icp_platform.h"
#include "icp_accel_devices.h"
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "adf_transport_ctrl.h"
#include "adf_platform.h"
#include "adf_dev_ring_ctl.h"

extern inline unsigned int modulo(unsigned int data, unsigned int shift);

/*
 * icp_adf_getQueueMemory
 * Data plane support function - returns the pointer to next message on the ring
 * or NULL if there is not enough space.
 */
void icp_adf_getQueueMemory(icp_comms_trans_handle trans_hnd,
                            Cpa32U numberRequests,
                            void **pCurrentQatMsg)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;
    Cpa32U **targetAddr = (Cpa32U **)pCurrentQatMsg;
    Cpa32U in_flight;

    /* Check if there is enough space in the ring */
    in_flight = *pRingHandle->in_flight + numberRequests;
    if (in_flight > pRingHandle->max_requests_inflight)
    {
        *targetAddr = NULL;
        return;
    }
    *pRingHandle->in_flight = in_flight;

    /* We have enough space - get the address of next message */
    *targetAddr = (Cpa32U *)(((UARCH_INT)pRingHandle->ring_virt_addr) +
                             pRingHandle->tail);
}

/*
 * icp_adf_getSingleQueueAddr
 * Data plane support function - returns the pointer to next message on the ring
 * or NULL if there is not enough space - it also updates the shadow tail copy.
 */
void icp_adf_getSingleQueueAddr(icp_comms_trans_handle trans_hnd,
                                void **pCurrentQatMsg)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;
    Cpa32U **targetAddr = (Cpa32U **)pCurrentQatMsg;
    Cpa32U in_flight;

    /* Check if there is enough space in the ring */
    in_flight = *pRingHandle->in_flight + 1;
    if (in_flight > pRingHandle->max_requests_inflight)
    {
        *targetAddr = NULL;
        return;
    }
    *pRingHandle->in_flight = in_flight;

    /* We have enough space - get the address of next message */
    *targetAddr = (Cpa32U *)(((UARCH_INT)pRingHandle->ring_virt_addr) +
                             pRingHandle->tail);

    /* Update the shadow tail */
    pRingHandle->tail = modulo((pRingHandle->tail + pRingHandle->message_size),
                               pRingHandle->modulo);
}

/*
 * icp_adf_getQueueNext
 * Data plane support function - increments the tail pointer and returns
 * the pointer to next message on the ring.
 */
void icp_adf_getQueueNext(icp_comms_trans_handle trans_hnd,
                          void **pCurrentQatMsg)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;
    Cpa32U **targetAddr = (Cpa32U **)pCurrentQatMsg;

    /* Increment tail to next message */
    pRingHandle->tail = modulo((pRingHandle->tail + pRingHandle->message_size),
                               pRingHandle->modulo);

    /* Get the address of next message */
    *targetAddr = (Cpa32U *)(((UARCH_INT)pRingHandle->ring_virt_addr) +
                             pRingHandle->tail);
}

/*
 * icp_adf_getDpInflightRequests
 * Data plane function to fetch in-flight and max in-flight request counts
 * for the given trans_handle.
 */
void icp_adf_getDpInflightRequests(icp_comms_trans_handle trans_hnd,
                                   Cpa32U *maxInflightRequests,
                                   Cpa32U *numInflightRequests)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;

    *numInflightRequests = *pRingHandle->in_flight;
    *maxInflightRequests = pRingHandle->max_requests_inflight;
}

/*
 * icp_adf_updateQueueTail
 * Data plane support function - Writes the tail shadow copy to the device.
 */
void icp_adf_updateQueueTail(icp_comms_trans_handle trans_hnd)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;

    WRITE_CSR_RING_TAIL(pRingHandle->csr_addr,
                        pRingHandle->bank_offset,
                        pRingHandle->ring_num,
                        pRingHandle->tail);

    pRingHandle->csrTailOffset = pRingHandle->tail;
}

/*
 * icp_adf_isRingEmpty
 * Data plane support function -  check if the ring is empty
 */
CpaBoolean icp_adf_isRingEmpty(icp_comms_trans_handle trans_hnd)
{
    Cpa32U mask = 0;
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;
    Cpa32U *csr_base_addr = ((Cpa32U *)pRingHandle->csr_addr);

    mask = READ_CSR_E_STAT(pRingHandle->bank_offset);
    mask = ~mask;

    if (mask & (1 << (pRingHandle->ring_num)))
    {
        return CPA_FALSE;
    }
    return CPA_TRUE;
}

/*
 * icp_adf_pollQueue
 * Data plane support function - Poll messages from the queue.
 */
CpaStatus icp_adf_pollQueue(icp_comms_trans_handle trans_hnd,
                            Cpa32U response_quota)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_hnd;
    Cpa32U msg_counter = 0;
    volatile Cpa32U *msg = NULL;

    if (response_quota == 0)
    {
        response_quota = ICP_NO_RESPONSE_QUOTA;
    }

    /* point to where the next message should be */
    msg = (Cpa32U *)(((UARCH_INT)pRingHandle->ring_virt_addr) +
                     pRingHandle->head);

    /* If there are valid messages then process them */
    while ((*msg != EMPTY_RING_ENTRY_SIG) && (msg_counter < response_quota))
    {
        /* Invoke the callback for the message */
        pRingHandle->callback((Cpa32U *)msg);

        /* Mark the message as processed */
        *msg = EMPTY_RING_ENTRY_SIG;

        /* Advance the head offset and handle wraparound */
        pRingHandle->head =
            modulo((pRingHandle->head + pRingHandle->message_size),
                   pRingHandle->modulo);
        msg_counter++;

        /* Point to where the next message should be */
        msg = (Cpa32U *)(((UARCH_INT)pRingHandle->ring_virt_addr) +
                         pRingHandle->head);
    }

    /* Update the head CSR if any messages were processed */
    if (msg_counter > 0)
    {
        *pRingHandle->in_flight -= msg_counter;

        /* Coalesce head writes to reduce impact of MMIO write */
        if (msg_counter > pRingHandle->coal_write_count)
        {
            pRingHandle->coal_write_count =
                pRingHandle->min_resps_per_head_write;

            WRITE_CSR_RING_HEAD(pRingHandle->csr_addr,
                                pRingHandle->bank_offset,
                                pRingHandle->ring_num,
                                pRingHandle->head);
        }
        else
        {
            /* Not enough responses have been processed to warrant the cost
             * of a head write. Updating the count for the next time. */
            pRingHandle->coal_write_count -= msg_counter;
        }
    }
    else
    {
        return CPA_STATUS_RETRY;
    }

    return CPA_STATUS_SUCCESS;
}

/*
 * icp_adf_queueDataToSend
 * Data-plane support function - Indicates if there is data on the ring to be
 * sent. This should only be called on request rings. If the function returns
 * true then it is ok to call icp_adf_updateQueueTail() function on this ring.
 */
CpaBoolean icp_adf_queueDataToSend(icp_comms_trans_handle trans_hnd)
{
    adf_dev_ring_handle_t *ringData = (adf_dev_ring_handle_t *)trans_hnd;

    if (ringData->tail != ringData->csrTailOffset)
        return CPA_TRUE;
    else
        return CPA_FALSE;
}
