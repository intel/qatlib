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
 * @file adf_user_transport_ctrl.c
 *
 * @description
 *      Transport Controller for user space
 *
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <sched.h>

#include "lac_sal_types.h"
#include "lac_sal.h"
#include "cpa.h"
#include "icp_platform.h"
#include "icp_accel_devices.h"
#include "icp_adf_accel_mgr.h"
#include "adf_kernel_types.h"
#include "icp_adf_init.h"
#include "icp_adf_transport.h"
#include "adf_transport_ctrl.h"
#include "adf_platform.h"
#include "adf_dev_ring_ctl.h"
#include "adf_user_transport.h"
#include "icp_adf_init.h"
#include "adf_devmgr.h"
#include "adf_io_bundles.h"
#include "adf_io_ring.h"

#include "adf_user_ring.h"
#include "adf_user_arbiter.h"
#include "adf_user_cfg.h"

STATIC Cpa32U *ringInflights[ADF_MAX_DEVICES] = {NULL};

extern void *adf_get_bank_base_addr(int accelId,
                                    int bankid,
                                    uint32_t *offset,
                                    uint32_t *size);
adf_dev_bank_handle_t *get_banks(icp_accel_dev_t *dev)
{
    return dev->banks;
}

STATIC CpaStatus init_rings_from_bank(icp_accel_dev_t *accel_dev,
                                      adf_dev_bank_handle_t *bank)
{
    uint32_t size = 0;

    size = sizeof(adf_dev_ring_handle_t *) * (accel_dev->maxNumRingsPerBank);
    bank->rings = ICP_MALLOC_GEN(size);
    if (NULL == bank->rings)
    {
        return CPA_STATUS_FAIL;
    }

    ICP_MEMSET(bank->rings, 0, size);
    return CPA_STATUS_SUCCESS;
}

CpaStatus init_bank_from_accel(icp_accel_dev_t *accel_dev,
                               adf_dev_bank_handle_t *bank)
{
    struct adf_io_user_bundle *bundle = NULL;

    bundle =
        adf_io_get_bundle_from_accelid(accel_dev->accelId, bank->bank_number);
    if (NULL == bundle)
        return CPA_STATUS_FAIL;

    if (adf_io_populate_bundle(accel_dev, bundle))
    {
        adf_io_free_bundle(bundle);
        return CPA_STATUS_FAIL;
    }

    bank->csr_addr = (uint32_t *)bundle->ptr;

    bank->csr_addr_shadow = (uint32_t *)ICP_MALLOC_GEN(ICP_BUNDLE_SIZE);
    if (NULL == bank->csr_addr_shadow)
    {
        adf_io_free_bundle(bundle);
        return CPA_STATUS_FAIL;
    }
    ICP_MEMSET(bank->csr_addr_shadow, 0, ICP_BUNDLE_SIZE);
    bank->bundle = bundle;

    /*  allocate ring handles for this bank  */
    if (CPA_STATUS_SUCCESS != init_rings_from_bank(accel_dev, bank))
    {
        adf_io_free_bundle(bundle);
        ICP_FREE(bank->csr_addr_shadow);
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus reinit_bank_from_accel(icp_accel_dev_t *accel_dev,
                                        adf_dev_bank_handle_t *bank)
{
    struct adf_io_user_bundle *bundle = NULL;

    bundle =
        adf_io_get_bundle_from_accelid(accel_dev->accelId, bank->bank_number);
    if (NULL == bundle)
    {
        return CPA_STATUS_FAIL;
    }
    bank->csr_addr = (uint32_t *)bundle->ptr;
    ICP_MEMSET(bank->csr_addr_shadow, 0, ICP_BUNDLE_SIZE);
    bank->bundle = bundle;

    /* allocate ring handles for this bank */
    if (CPA_STATUS_SUCCESS != init_rings_from_bank(accel_dev, bank))
    {
        adf_io_free_bundle(bank->bundle);
        bank->bundle = NULL;
        return CPA_STATUS_FAIL;
    }

    bank->num_rings_per_bank = accel_dev->maxNumRingsPerBank;

    return CPA_STATUS_SUCCESS;
}

static void adf_proxy_set_bank_default_info(icp_accel_dev_t *dev)
{
    adf_dev_bank_handle_t *banks = dev->banks;
    int32_t i;

    for (i = 0; i < dev->maxNumBanks; i++, banks++)
    {
        banks->bank_number = i;
        banks->bank_offset = 0;
        banks->tx_rings_mask = 0xff;
        banks->ring_mask = 0;
    }
}

STATIC CpaStatus adf_proxy_populate_bank_ring_info(icp_accel_dev_t *accel_dev)
{
    adf_dev_bank_handle_t *bankHandler;
    Cpa32U *inflight;
    Cpa32U numOfBanksPerDevice = 0;
    Cpa32U size = 0;
    Cpa32U device_id = 0;

    device_id = accel_dev->accelId;
    numOfBanksPerDevice = accel_dev->maxNumBanks;

    /* allocate bank handler array */
    size = sizeof(adf_dev_bank_handle_t) * numOfBanksPerDevice;
    bankHandler = ICP_MALLOC_GEN(size);
    if (NULL == bankHandler)
    {
        ADF_ERROR("Failed to allocate memory - bankHandler\n");
        return CPA_STATUS_FAIL;
    }
    ICP_MEMSET(bankHandler, 0, size);
    accel_dev->banks = bankHandler;
    adf_proxy_set_bank_default_info(accel_dev);

    /* allocate ring inflight array ring put/get optimization */
    size = sizeof(*inflight) * (accel_dev->maxNumRingsPerBank >> 1) *
           numOfBanksPerDevice;
    inflight = ICP_MALLOC_GEN(size);
    if (NULL == inflight)
    {
        ADF_ERROR("Failed to allocate memory - ringInflights\n");
        ICP_FREE(accel_dev->banks);
        return CPA_STATUS_FAIL;
    }

    ringInflights[device_id] = inflight;

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_proxy_populate_device_info(icp_accel_dev_t *accel_dev)
{
    return adf_proxy_populate_bank_ring_info(accel_dev);
}

STATIC void adf_proxy_repopulate_bank_ring_info(icp_accel_dev_t *accel_dev)
{
    adf_proxy_set_bank_default_info(accel_dev);
}

STATIC void adf_proxy_repopulate_device_info(icp_accel_dev_t *accel_dev)
{
    adf_proxy_repopulate_bank_ring_info(accel_dev);
}

void adf_proxy_depopulate_bank_ring_info(icp_accel_dev_t *accel_dev)
{
    Cpa32U device_id = 0;

    device_id = accel_dev->accelId;
    ICP_FREE(accel_dev->banks);
    ICP_FREE(ringInflights[device_id]);

    return;
}

void adf_proxy_depopulate_device_info(icp_accel_dev_t *accel_dev)
{
    adf_proxy_depopulate_bank_ring_info(accel_dev);
    return;
}

STATIC INLINE int adf_dev_bank_handle_get(adf_dev_bank_handle_t *bank)
{
    return __sync_fetch_and_add(&bank->refs, 1);
}

STATIC INLINE int adf_dev_bank_handle_put(adf_dev_bank_handle_t *bank)
{
    return __sync_fetch_and_sub(&bank->refs, 1);
}

STATIC INLINE int adf_dev_bank_handle_check(adf_dev_bank_handle_t *bank)
{
    return __sync_val_compare_and_swap(&bank->refs, 0, 0);
}

/*
 * Check and free the ring and bundle
 * This function is used to free the bundle and ring in the bank
 * handle when the reference count is set as ZERO.
 */
STATIC void adf_free_bundle(adf_dev_bank_handle_t *bank)
{
    if (0 != adf_dev_bank_handle_check(bank))
    {
        return;
    }

    if (bank->rings)
    {
        ICP_FREE(bank->rings);
        bank->rings = NULL;
    }
    if (bank->bundle)
    {
        adf_io_free_bundle(bank->bundle);
        bank->bundle = NULL;
    }
    if (bank->csr_addr_shadow)
    {
        ICP_FREE(bank->csr_addr_shadow);
        bank->csr_addr_shadow = NULL;
    }
    return;
}

STATIC void adf_clean_bundle(adf_dev_bank_handle_t *bank)
{
    if (0 == adf_dev_bank_handle_check(bank))
    {
        ICP_FREE(bank->rings);
        bank->csr_addr = bank->csr_addr_shadow;
        adf_io_free_bundle(bank->bundle);
        bank->bundle = NULL;
        bank->rings = NULL;
    }
    return;
}

STATIC CpaStatus
adf_populate_ring_info_internal(adf_dev_ring_handle_t *pRingHandle,
                                icp_accel_dev_t *accel_dev,
                                icp_transport_type trans_type,
                                icp_trans_callback callback,
                                const char *section,
                                const char *service_name,
                                const Cpa32U accel_nr,
                                const Cpa32U bank_nr,
                                icp_resp_deliv_method resp,
                                const icp_adf_ringInfoService_t info,
                                const Cpa32U num_msgs,
                                const Cpa32U msg_size,
                                int ring_rnum)
{
    size_t len = 0;
    Cpa32U in_flight_index = 0;

    pRingHandle->is_wireless = 0;
    pRingHandle->is_dyn = 0;
    pRingHandle->ringResponseQuota = 0;
    pRingHandle->coal_write_count = 0;
    pRingHandle->csrTailOffset = 0;

    pRingHandle->accel_dev = accel_dev;
    pRingHandle->trans_type = trans_type;

    len = ICP_STRNLEN(service_name, ICP_MAX_STR_LEN) + 1;
    memcpy(pRingHandle->service_name, service_name, len);
    pRingHandle->service_name_len = len;

    len = ICP_STRNLEN(section, ICP_MAX_STR_LEN) + 1;
    memcpy(pRingHandle->section_name, section, len);
    pRingHandle->section_name_len = len;

    pRingHandle->callback = callback;
    pRingHandle->accel_num = accel_nr;
    pRingHandle->bank_num = bank_nr;

    pRingHandle->resp = resp;
    pRingHandle->info = info;
    if (ICP_RESP_TYPE_POLL == resp)
    {
        /* Set the polling mask for this ring handle. */
        pRingHandle->pollingMask = 1 << ring_rnum;
    }
    else if (ICP_RESP_TYPE_IRQ == resp)
    {
        /* epoll rings are also polled, so we neeed to set both
         * their polling and interrupt mask
         */
        pRingHandle->pollingMask = 1 << ring_rnum;
        pRingHandle->interrupt_user_mask = 1 << ring_rnum;
    }
    else if (ICP_RESP_TYPE_NONE != resp)
    {
        ADF_ERROR("Not implemented yet\n");
        return CPA_STATUS_FAIL;
    }

    /* To save size we are going to reuse the ring space var
     * to pass down the ring num_msgs. space is in bytes
     * and is only used later in the msg put and get logic.
     * num_msgs is used only to allocate appropriate
     * memory for the ring and is not subsequently stored
     */
    pRingHandle->space = num_msgs;
    pRingHandle->message_size = msg_size;
    pRingHandle->ring_num = ring_rnum;

    /* request and response ring will share the same index */
    if (pRingHandle->ring_num < accel_dev->maxNumRingsPerBank / 2)
    {
        in_flight_index =
            ((accel_dev->maxNumRingsPerBank * pRingHandle->bank_num) >> 1) +
            pRingHandle->ring_num;
    }
    else
    {
        in_flight_index =
            ((accel_dev->maxNumRingsPerBank * pRingHandle->bank_num) >> 1) +
            (pRingHandle->ring_num - accel_dev->maxNumRingsPerBank / 2);
    }
    /* Initialise the pRingHandle inflight */
    pRingHandle->in_flight =
        ringInflights[accel_dev->accelId] + in_flight_index;
    *pRingHandle->in_flight = 0;
    /* Initialise the pRingHandle atomic flag. */
    osalAtomicSet(1, (OsalAtomic *)&(pRingHandle->pollingInProgress));

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_populate_ring_info(adf_dev_ring_handle_t *pRingHandle,
                                        icp_accel_dev_t *accel_dev,
                                        icp_transport_type trans_type,
                                        icp_trans_callback callback,
                                        const char *section,
                                        const char *service_name,
                                        const Cpa32U accel_nr,
                                        const Cpa32U bank_nr,
                                        icp_resp_deliv_method resp,
                                        const icp_adf_ringInfoService_t info,
                                        const Cpa32U num_msgs,
                                        const Cpa32U msg_size,
                                        int ring_rnum)
{
    size_t len = 0;

    len = ICP_STRNLEN(service_name, ICP_MAX_STR_LEN) + 1;
    pRingHandle->service_name = ICP_MALLOC_GEN(len);

    if (NULL == pRingHandle->service_name)
    {
        ADF_ERROR("unable to allocate service buffer\n");
        return CPA_STATUS_FAIL;
    }

    len = ICP_STRNLEN(section, ICP_MAX_STR_LEN) + 1;
    pRingHandle->section_name = ICP_MALLOC_GEN(len);

    if (NULL == pRingHandle->section_name)
    {
        ICP_FREE(pRingHandle->service_name);
        ADF_ERROR("unable to allocate section name buffer\n");
        return CPA_STATUS_FAIL;
    }

    pRingHandle->user_lock = ICP_MALLOC_GEN(sizeof(ICP_MUTEX));

    if (!pRingHandle->user_lock)
    {
        ICP_FREE(pRingHandle->service_name);
        ICP_FREE(pRingHandle->section_name);
        ADF_ERROR("Could not alloc memory for ring lock\n");
        return CPA_STATUS_FAIL;
    }
    if (OSAL_SUCCESS != ICP_MUTEX_INIT(pRingHandle->user_lock))
    {
        ICP_FREE(pRingHandle->service_name);
        ICP_FREE(pRingHandle->section_name);
        ICP_FREE(pRingHandle->user_lock);
        ADF_ERROR("Mutex init failed for user_lock\n");
        return CPA_STATUS_RESOURCE;
    }

    if (CPA_STATUS_SUCCESS != adf_populate_ring_info_internal(pRingHandle,
                                                              accel_dev,
                                                              trans_type,
                                                              callback,
                                                              section,
                                                              service_name,
                                                              accel_nr,
                                                              bank_nr,
                                                              resp,
                                                              info,
                                                              num_msgs,
                                                              msg_size,
                                                              ring_rnum))
    {
        ICP_FREE(pRingHandle->service_name);
        ICP_FREE(pRingHandle->section_name);
        ICP_MUTEX_UNINIT(pRingHandle->user_lock);
        ICP_FREE(pRingHandle->user_lock);
        ADF_ERROR("Failed to populate the ring info\n");
        return CPA_STATUS_FAIL;
    };

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus adf_repopulate_ring_info(adf_dev_ring_handle_t *pRingHandle,
                                          icp_accel_dev_t *accel_dev,
                                          icp_transport_type trans_type,
                                          icp_trans_callback callback,
                                          const char *section,
                                          const char *service_name,
                                          const Cpa32U accel_nr,
                                          const Cpa32U bank_nr,
                                          icp_resp_deliv_method resp,
                                          const icp_adf_ringInfoService_t info,
                                          const Cpa32U num_msgs,
                                          const Cpa32U msg_size,
                                          int ring_rnum)
{
    return adf_populate_ring_info_internal(pRingHandle,
                                           accel_dev,
                                           trans_type,
                                           callback,
                                           section,
                                           service_name,
                                           accel_nr,
                                           bank_nr,
                                           resp,
                                           info,
                                           num_msgs,
                                           msg_size,
                                           ring_rnum);
}

/*
 * Create a transport handle
 * The function sends ioctl request to adf user proxy to create
 * a ring and then mmaps it to userspace memory. If it is a response
 * ring and there is no reading thread running for the device
 * the function creates one.
 */
CpaStatus icp_adf_transCreateHandle(icp_accel_dev_t *accel_dev,
                                    icp_transport_type trans_type,
                                    const char *section,
                                    const Cpa32U accel_nr,
                                    const Cpa32U bank_nr,
                                    const char *service_name,
                                    const icp_adf_ringInfoService_t info,
                                    icp_trans_callback callback,
                                    icp_resp_deliv_method resp,
                                    const Cpa32U num_msgs,
                                    const Cpa32U msg_size,
                                    icp_comms_trans_handle *trans_handle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    Cpa32U ring_number = 0;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(trans_handle);

    adf_dev_bank_handle_t *banks = accel_dev->banks;
    adf_dev_bank_handle_t *bank = &banks[bank_nr];
    int nodeid = accel_dev->numa_node;
    int ring_rnum = 0;
    char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

    /* here init the bank: get a free bundle from UIO and mmap it
     * It's not suitable to put it into device init stage,
     * for at that time, we don't know which device the user will be use */
    if (NULL == bank->bundle)
    {
        ICP_MUTEX_LOCK(bank->user_bank_lock);
        if (0 > init_bank_from_accel(accel_dev, bank))
        {
            ICP_MUTEX_UNLOCK(bank->user_bank_lock);
            return CPA_STATUS_FAIL;
        }
        ICP_MUTEX_UNLOCK(bank->user_bank_lock);
    }

    if (CPA_STATUS_SUCCESS ==
        icp_adf_cfgGetParamValue(accel_dev, section, service_name, val))
    {
        ring_rnum = strtoul(val, NULL, 10);
        if ((ring_rnum < 0) || (ring_rnum >= accel_dev->maxNumRingsPerBank))
        {
            ADF_ERROR("Invalid ring num\n");
            adf_free_bundle(bank);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        adf_free_bundle(bank);
        return CPA_STATUS_FAIL;
    }

    /* Reserve the ring in the kernel driver */
    if (CPA_STATUS_SUCCESS !=
        adf_io_reserve_ring(accel_dev->accelId, bank_nr, ring_rnum))
    {
        adf_free_bundle(bank);
        return CPA_STATUS_FAIL;
    }

    /* allocate and setup ring handle structure */
    pRingHandle = ICP_MALLOC_GEN(sizeof(adf_dev_ring_handle_t));

    if (NULL == pRingHandle)
    {
        ADF_ERROR("unable to allocate pRingHandle buffer\n");
        if (CPA_STATUS_SUCCESS !=
            adf_io_release_ring(accel_dev->accelId, bank_nr, ring_rnum))
        {
            ADF_ERROR("Failed to release the ring \n");
        }
        adf_free_bundle(bank);
        return CPA_STATUS_FAIL;
    }
    ICP_MEMSET(pRingHandle, 0, sizeof(adf_dev_ring_handle_t));

    if (CPA_STATUS_SUCCESS != adf_populate_ring_info(pRingHandle,
                                                     accel_dev,
                                                     trans_type,
                                                     callback,
                                                     section,
                                                     service_name,
                                                     accel_nr,
                                                     bank_nr,
                                                     resp,
                                                     info,
                                                     num_msgs,
                                                     msg_size,
                                                     ring_rnum))
    {
        ICP_FREE(pRingHandle);
        if (CPA_STATUS_SUCCESS !=
            adf_io_release_ring(accel_dev->accelId, bank_nr, ring_rnum))
        {
            ADF_ERROR("Failed to release the ring \n");
        }
        adf_free_bundle(bank);
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != adf_init_ring(pRingHandle,
                                            bank,
                                            ring_rnum,
                                            bank->csr_addr,
                                            num_msgs,
                                            msg_size,
                                            nodeid))
    {
        ADF_ERROR("adf_init_ring failed\n");
        ICP_FREE(pRingHandle->section_name);
        ICP_FREE(pRingHandle->service_name);
        ICP_FREE(pRingHandle->user_lock);
        ICP_FREE(pRingHandle);
        if (CPA_STATUS_SUCCESS !=
            adf_io_release_ring(accel_dev->accelId, bank_nr, ring_rnum))
        {
            ADF_ERROR("Failed to release the ring \n");
        }
        adf_free_bundle(bank);
        return CPA_STATUS_FAIL;
    }

    adf_dev_bank_handle_get(bank);
    *trans_handle = (icp_comms_trans_handle *)pRingHandle;
    status = icp_adf_transGetRingNum(*trans_handle, &ring_number);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("icp_adf_transGetRingNum failed\n");
        icp_adf_transReleaseHandle(*trans_handle);
        *trans_handle = NULL;
        return CPA_STATUS_FAIL;
    }

    /* callback has been overwritten in kernelspace
     * so have to set it to the userspace callback again */
    pRingHandle->callback = callback;
    (bank->rings)[ring_rnum] = pRingHandle;
    banks[pRingHandle->bank_num].interrupt_mask |=
        pRingHandle->interrupt_user_mask;
    banks[pRingHandle->bank_num].pollingMask |= pRingHandle->pollingMask;

    /* Configure interrupts in the hardware only for epoll mode */
    if (ICP_RESP_TYPE_IRQ == resp)
    {
        uint32_t *csr_base_addr = pRingHandle->csr_addr;
        WRITE_CSR_INT_COL_EN(pRingHandle->bank_offset,
                             banks[pRingHandle->bank_num].interrupt_mask);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus icp_adf_transReinitHandle(icp_accel_dev_t *accel_dev,
                                    icp_transport_type trans_type,
                                    const char *section,
                                    const Cpa32U accel_nr,
                                    const Cpa32U bank_nr,
                                    const char *service_name,
                                    const icp_adf_ringInfoService_t info,
                                    icp_trans_callback callback,
                                    icp_resp_deliv_method resp,
                                    const Cpa32U num_msgs,
                                    const Cpa32U msg_size,
                                    icp_comms_trans_handle *trans_handle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    Cpa32U ring_number = 0;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    ICP_CHECK_FOR_NULL_PARAM(trans_handle);

    adf_dev_bank_handle_t *banks = accel_dev->banks;
    adf_dev_bank_handle_t *bank = &banks[bank_nr];
    int nodeid = accel_dev->numa_node;
    int ring_rnum = 0;
    char val[ADF_CFG_MAX_VAL_LEN_IN_BYTES];

    pRingHandle = *trans_handle;

    /* here init the bank: get a free bundle from UIO and mmap it
     * It's not suitable to put it into device init stage,
     * for at that time, we don't know which device the user will be use */
    if (NULL == bank->bundle)
    {
        ICP_MUTEX_LOCK(bank->user_bank_lock);
        if (CPA_STATUS_SUCCESS != reinit_bank_from_accel(accel_dev, bank))
        {
            ICP_MUTEX_UNLOCK(bank->user_bank_lock);
            icp_adf_transReleaseHandle(pRingHandle);
            return CPA_STATUS_FAIL;
        }
        ICP_MUTEX_UNLOCK(bank->user_bank_lock);
    }
    adf_dev_bank_handle_get(bank);

    if (CPA_STATUS_SUCCESS ==
        icp_adf_cfgGetParamValue(accel_dev, section, service_name, val))
    {
        ring_rnum = strtoul(val, NULL, 10);
        if ((ring_rnum < 0) || (ring_rnum >= accel_dev->maxNumRingsPerBank))
        {
            ADF_ERROR("Invalid ring num\n");
            icp_adf_transReleaseHandle(pRingHandle);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        icp_adf_transReleaseHandle(pRingHandle);
        return CPA_STATUS_FAIL;
    }

    /* Reserve the ring in the kernel driver */
    if (CPA_STATUS_SUCCESS !=
        adf_io_reserve_ring(accel_dev->accelId, bank_nr, ring_rnum))
    {
        icp_adf_transReleaseHandle(pRingHandle);
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != adf_repopulate_ring_info(pRingHandle,
                                                       accel_dev,
                                                       trans_type,
                                                       callback,
                                                       section,
                                                       service_name,
                                                       accel_nr,
                                                       bank_nr,
                                                       resp,
                                                       info,
                                                       num_msgs,
                                                       msg_size,
                                                       ring_rnum))
    {
        icp_adf_transReleaseHandle(pRingHandle);
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS != adf_reinit_ring(pRingHandle,
                                              bank,
                                              ring_rnum,
                                              bank->csr_addr,
                                              num_msgs,
                                              msg_size,
                                              nodeid))
    {
        ADF_ERROR("adf_init_ring failed\n");
        icp_adf_transReleaseHandle(pRingHandle);
        return CPA_STATUS_FAIL;
    }

    pRingHandle->accel_dev = accel_dev;
    *trans_handle = (icp_comms_trans_handle *)pRingHandle;
    status = icp_adf_transGetRingNum(*trans_handle, &ring_number);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("icp_adf_transGetRingNum failed\n");
        icp_adf_transReleaseHandle(*trans_handle);
        *trans_handle = NULL;
        return CPA_STATUS_FAIL;
    }

    /* callback has been overwritten in kernelspace
     * so have to set it to the userspace callback again */
    pRingHandle->callback = callback;
    (bank->rings)[ring_rnum] = pRingHandle;
    banks[pRingHandle->bank_num].interrupt_mask |=
        pRingHandle->interrupt_user_mask;
    banks[pRingHandle->bank_num].pollingMask |= pRingHandle->pollingMask;

    /* Configure interrupts in the hardware only for epoll mode */
    if (ICP_RESP_TYPE_IRQ == resp)
    {
        uint32_t *csr_base_addr = pRingHandle->csr_addr;
        WRITE_CSR_INT_COL_EN(pRingHandle->bank_offset,
                             banks[pRingHandle->bank_num].interrupt_mask);
    }

    return CPA_STATUS_SUCCESS;
}

STATIC CpaStatus icp_adf_transCleanHandle(icp_comms_trans_handle trans_handle)
{
    int ret = 0;
    icp_accel_dev_t *accel_dev = NULL;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    adf_dev_bank_handle_t *pbanks = NULL;
    Cpa32U ring_number;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);
    pRingHandle = (adf_dev_ring_handle_t *)trans_handle;
    ICP_CHECK_FOR_NULL_PARAM(pRingHandle->accel_dev);
    accel_dev = pRingHandle->accel_dev;
    ret = icp_adf_transGetRingNum(pRingHandle, &ring_number);
    if (CPA_STATUS_SUCCESS != ret)
    {
        ADF_ERROR("icp_adf_transGetRingNum failed\n");
        return ret;
    }

    pbanks = accel_dev->banks;

    /* update user process IRQ mask
     * Everytime userspace ring gets a message it reads it from the ring
     * and as the last step needs to enable the IRQ for the ring so
     * the driver could get notifications that there is data on the ring.
     * So this is important to keep the IRQ mask up to date */
    pbanks[pRingHandle->bank_num].interrupt_mask &=
        (~(1 << pRingHandle->ring_num));
    pbanks[pRingHandle->bank_num].pollingMask &=
        (~(1 << pRingHandle->ring_num));
    /* send the request down to the kernel.
     * NOTE: Don't send release_handle if the kernel proxy is not running
     * The proxy down there will cleanup the rings anyway.
     * */
    ret = adf_io_release_ring(
        accel_dev->accelId, pRingHandle->bank_num, pRingHandle->ring_num);
    if (CPA_STATUS_SUCCESS != ret)
    {
        ADF_ERROR("Failed to release the ring \n");
    }
    return ret;
}

/*
 * Release a transport handle
 * The function sends ioctl request to adf user proxy to release a ring
 */
CpaStatus icp_adf_transReleaseHandle(icp_comms_trans_handle trans_handle)
{
    icp_accel_dev_t *accel_dev = NULL;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    adf_dev_bank_handle_t *pbanks = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);
    pRingHandle = (adf_dev_ring_handle_t *)trans_handle;
    ICP_CHECK_FOR_NULL_PARAM(pRingHandle->accel_dev);
    accel_dev = pRingHandle->accel_dev;

    status = icp_adf_transCleanHandle(trans_handle);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("icp_adf_transCleanHandle failed \n");
    }

    adf_cleanup_ring(pRingHandle);
    if (NULL != pRingHandle->service_name)
    {
        ICP_FREE(pRingHandle->service_name);
        ICP_FREE(pRingHandle->section_name);
    }

    if (NULL != pRingHandle->user_lock)
    {
        ICP_MUTEX_UNINIT(pRingHandle->user_lock);
        ICP_FREE(pRingHandle->user_lock);
    }

    pbanks = accel_dev->banks;
    if (NULL != pbanks)
    {
        pbanks = pbanks + pRingHandle->bank_num;
        if (NULL != pbanks->rings)
        {
            pbanks->rings[pRingHandle->ring_num] = NULL;
            adf_dev_bank_handle_put(pbanks);
        }
        adf_free_bundle(pbanks);
    }

    ICP_FREE(pRingHandle);
    return status;
}

/*
 * Reset a transport handle
 * The function resets some of the contents of the ring and also sends
 * ioctl request to adf user proxy to release a ring
 */
CpaStatus icp_adf_transResetHandle(icp_comms_trans_handle trans_handle)
{
    icp_accel_dev_t *accel_dev = NULL;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    adf_dev_bank_handle_t *pbanks = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);
    pRingHandle = (adf_dev_ring_handle_t *)trans_handle;
    ICP_CHECK_FOR_NULL_PARAM(pRingHandle->accel_dev);
    accel_dev = pRingHandle->accel_dev;

    status = icp_adf_transCleanHandle(trans_handle);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("icp_adf_transCleanHandle failed \n");
    }

    adf_reset_ring(pRingHandle);
    if (NULL != pRingHandle->service_name)
    {
        ICP_MEMSET(
            pRingHandle->service_name, 0, strlen(pRingHandle->service_name));
        ICP_MEMSET(
            pRingHandle->section_name, 0, strlen(pRingHandle->section_name));
    }

    pbanks = accel_dev->banks;
    if (NULL != pbanks)
    {
        pbanks = pbanks + pRingHandle->bank_num;

        if (NULL != pbanks->rings)
        {
            pbanks->rings[pRingHandle->ring_num] = NULL;
            adf_dev_bank_handle_put(pbanks);
            adf_clean_bundle(pbanks);
        }
    }

    return status;
}

/*
 * Returns ring number for the trans handle
 */
CpaStatus icp_adf_transGetRingNum(icp_comms_trans_handle trans_handle,
                                  Cpa32U *ringNum)
{
    adf_dev_ring_handle_t *pRingHandle = NULL;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);
    pRingHandle = (adf_dev_ring_handle_t *)trans_handle;
    *ringNum =
        (pRingHandle->bank_num * pRingHandle->accel_dev->maxNumRingsPerBank) +
        pRingHandle->ring_num;
    return CPA_STATUS_SUCCESS;
}

/*
 * Put a message on the transport handle
 */
CpaStatus icp_adf_transPutMsg(icp_comms_trans_handle trans_handle,
                              Cpa32U *inBuf,
                              Cpa32U bufLen,
                              Cpa64U *seq_num)
{
    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_handle;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);
    ICP_CHECK_PARAM_RANGE(bufLen * ICP_ADF_BYTES_PER_WORD,
                          pRingHandle->message_size,
                          pRingHandle->message_size);
    return adf_user_put_msg(pRingHandle, inBuf, seq_num);
}

/*
 * icp_adf_getInflightRequests
 * Function to fetch in-flight and max in-flight request counts for the
 * given trans_handle.
 */
CpaStatus icp_adf_getInflightRequests(icp_comms_trans_handle trans_handle,
                                      Cpa32U *maxInflightRequests,
                                      Cpa32U *numInflightRequests)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    adf_dev_ring_handle_t *pRingHandle = (adf_dev_ring_handle_t *)trans_handle;

    ICP_CHECK_FOR_NULL_PARAM(trans_handle);

    status = adf_user_get_inflight_requests(
        pRingHandle, maxInflightRequests, numInflightRequests);
    if (CPA_STATUS_SUCCESS != status)
    {
        ADF_ERROR("adf_user_get_inflight_requests failed with %d status\n",
                  status);
    }
    return status;
}

/*
 * adf_user_unmap_rings
 * Device is going down - unmap all rings allocated for this device
 */
CpaStatus adf_user_unmap_rings(icp_accel_dev_t *accel_dev)
{
    CpaStatus stat = CPA_STATUS_SUCCESS;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    adf_dev_bank_handle_t *bank = NULL;
    int i = 0, l = 0;

    bank = accel_dev->banks;
    for (i = 0; i < accel_dev->maxNumBanks; i++)
    {
        if (NULL == bank->rings)
            continue;

        for (l = 0; l < accel_dev->maxNumRingsPerBank; l++)
        {
            pRingHandle = (bank->rings)[i];
            if (pRingHandle)
                adf_ring_freebuf(pRingHandle);
        }
    }
    return stat;
}

/*
 * Internal functions which performs all the
 * tasks necessary to poll a response ring.
 */
CpaStatus adf_pollRing(icp_accel_dev_t *accel_dev,
                       adf_dev_ring_handle_t *pRingHandle,
                       Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_RETRY;

    /* Check to see if this ring is already being polled by
     * another core or thread. DecAndTest returns TRUE
     * only if pRingHandle->pollingInProgress was previously
     * equal to one and then sets the var to zero. While
     * pRingHandle->pollingInProgress is still zero no other
     * thread will be able to poll. pollingInProgress is
     * reset to one once the notify function is done.
     */
    if (osalAtomicDecAndTest((OsalAtomic *)&(pRingHandle->pollingInProgress)))
    {
        /* Set the ring response quota. */
        pRingHandle->ringResponseQuota = response_quota;
        status = adf_user_notify_msgs_poll(pRingHandle);
        osalAtomicSet(1, (OsalAtomic *)&(pRingHandle->pollingInProgress));
    }
    return status;
}
/*
 * This function allows the user to poll the response rings of a given
 * bank to determine if any of the rings have messages that need to be
 * read. This method is used as an alternative to reading messages
 * via the ISR method.
 * N.B. response quota is per ring.
 */
CpaStatus icp_sal_pollBank(Cpa32U accelId,
                           Cpa32U bank_number,
                           Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_RETRY;
    icp_accel_dev_t *accel_dev = NULL;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;
    adf_dev_ring_handle_t *pRingHandle = NULL;
    Cpa32U csrVal = 0;
    Cpa32U ringnum_in_bank = 0;
    Cpa32U stat_total = 0;

    /* Find the accel device associated with the accelId
     * passed in.
     */
    accel_dev = adf_devmgrGetAccelDevByAccelId(accelId);
    if (!accel_dev)
    {
        ADF_ERROR("There is no accel device associated"
                  " with this accel id.\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    ICP_CHECK_PARAM_LT_MAX(bank_number, accel_dev->maxNumBanks);
    banks = accel_dev->banks;
    bank = &banks[bank_number];
    ICP_MUTEX_LOCK(bank->user_bank_lock);

    /* Read the ring status CSR to determine which rings are empty. */
    csrVal = READ_CSR_E_STAT_EXT(bank->csr_addr, bank->bank_offset);
    /* Complement to find which rings have data to be processed. */
    csrVal = ~csrVal;
    /* Return RETRY if the bank polling rings
     * are all empty. */
    if (!(csrVal & bank->pollingMask))
    {
        ICP_MUTEX_UNLOCK(bank->user_bank_lock);
        return CPA_STATUS_RETRY;
    }

    /*
     * Loop over all rings within this bank.
     * The ringHandles structure is global to all
     * rings hence while we loop over all rings in the
     * bank we use ring_number to get the global
     * RingHandle.
     */
    for (ringnum_in_bank = 0; ringnum_in_bank < accel_dev->maxNumRingsPerBank;
         ringnum_in_bank++)
    {
        pRingHandle = (bank->rings)[ringnum_in_bank];
        /* If this ring has not being created move to next ring. */
        if (NULL == pRingHandle)
        {
            continue;
        }
        /* And with polling ring mask
         * If the there is no data on this ring move to the next one */
        if (!(csrVal & pRingHandle->pollingMask))
        {
            continue;
        }
        /* Poll the ring */
        status = adf_pollRing(accel_dev, pRingHandle, response_quota);
        if (CPA_STATUS_SUCCESS == status)
        {
            stat_total++;
        }

        /* Re-enable interrupts in case we are using epoll mode */
        if (ICP_RESP_TYPE_IRQ == pRingHandle->resp)
        {
            WRITE_CSR_INT_COL_EN_EXT(
                bank->csr_addr, pRingHandle->bank_offset, bank->interrupt_mask);
        }
    }
    /* Return SUCCESS if adf_pollRing returned SUCCESS at any stage */
    ICP_MUTEX_UNLOCK(bank->user_bank_lock);
    if (stat_total)
    {
        return CPA_STATUS_SUCCESS;
    }
    return CPA_STATUS_RETRY;
}

/*
 * This function allows the user to poll all the response rings
 * belonging to a process per device.
 * This method is used as an alternative to the reading messages
 * via the ISR method.
 * N.B. response_quota is per ring.
 */
CpaStatus icp_sal_pollAllBanks(Cpa32U accelId, Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_RETRY;
    icp_accel_dev_t *accel_dev = NULL;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;
    Cpa32U bank_num = 0;
    Cpa32U stat_total = 0;

    /* Find the accel device associated with the accelId
     * passed in.
     */
    accel_dev = adf_devmgrGetAccelDevByAccelId(accelId);
    if (!accel_dev)
    {
        ADF_ERROR("There is no accel device associated"
                  " with this accel id.\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    if (icp_adf_isDevInError(accel_dev))
    {
        ADF_DEBUG("Pollbank: generate dummy responses\n");
#ifndef ICP_DC_ONLY
        status = Lac_CyPollAllBanks_GenResponses(accel_dev);
        if (CPA_STATUS_SUCCESS != status)
        {
            ADF_ERROR("Failed to generate responses by polling bank\n");
            return status;
        }
#endif
        return CPA_STATUS_RETRY;
    }

    /* Loop over banks and call icp_sal_pollBank. */
    banks = accel_dev->banks;

    for (bank_num = 0; bank_num < accel_dev->maxNumBanks; bank_num++)
    {
        bank = &(banks)[bank_num];
        /* if there are no polling rings on this bank
         * continue to the next bank number. */
        if (bank->pollingMask == 0)
        {
            continue;
        }
        status = icp_sal_pollBank(accelId, bank_num, response_quota);
        if (CPA_STATUS_SUCCESS == status)
        {
            stat_total++;
        }
    }
    /* Return SUCCESS if icp_sal_pollBank returned SUCCESS
     * at any stage. icp_sal_pollBank cannot
     * return fail in the above case. */
    if (stat_total)
    {
        return CPA_STATUS_SUCCESS;
    }
    return CPA_STATUS_RETRY;
}

/*
 * This will set the fd of the UIO device this instance
 * handler is using. If more than one transaction handler
 * are ever present, this will need to be refactored to
 * return the appropiate fd of the appropiate bank
 */
CpaStatus icp_adf_transGetFdForHandle(icp_comms_trans_handle trans_hnd, int *fd)
{
    int local_fd = -1;
    adf_dev_ring_handle_t *ring_handle = (adf_dev_ring_handle_t *)trans_hnd;
    struct adf_io_user_bundle *bundle =
        (struct adf_io_user_bundle *)ring_handle->bank_data->bundle;
    local_fd = bundle->fd;

    if (local_fd >= 0)
    {
        *fd = local_fd;
        return CPA_STATUS_SUCCESS;
    }
    else
    {
        return CPA_STATUS_FAIL;
    }
}

/*
 * This function allows the user to poll the response ring. The
 * ring number to be polled is supplied by the user via the
 * trans handle for that ring. The trans_hnd is a pointer
 * to an array of trans handles. This ring is
 * only polled if it contains data.
 * This method is used as an alternative to the reading messages
 * via the ISR method.
 * This function will return RETRY if the ring is empty.
 */
CpaStatus icp_adf_pollInstance(icp_comms_trans_handle *trans_hnd,
                               Cpa32U num_transHandles,
                               Cpa32U response_quota)
{
    CpaStatus status = CPA_STATUS_RETRY;
    adf_dev_ring_handle_t *ring_hnd = NULL;
    adf_dev_ring_handle_t *ring_hnd_first = NULL;
    Cpa8U *csr_base_addr = NULL;
    Cpa32U i = 0;
    Cpa32U stat_total = 0;

    ICP_CHECK_FOR_NULL_PARAM(trans_hnd);
    ring_hnd_first = (adf_dev_ring_handle_t *)trans_hnd[0];
    if (!ring_hnd_first)
    {
        return CPA_STATUS_FAIL;
    }

    ICP_MUTEX_LOCK(ring_hnd_first->user_lock);
    csr_base_addr = (Cpa8U *)ring_hnd_first->csr_addr;

    for (i = 0; i < num_transHandles; i++)
    {
        ring_hnd = (adf_dev_ring_handle_t *)trans_hnd[i];
        if (!ring_hnd)
        {
            ICP_MUTEX_UNLOCK(ring_hnd_first->user_lock);
            return CPA_STATUS_FAIL;
        }
        /* And with polling ring mask. If the
         * polling ring has no data move to the
         * next ring handle.*/
        if (!ring_hnd->pollingMask)
        {
            continue;
        }
        /* Poll the ring. */
        status = adf_pollRing(ring_hnd->accel_dev, ring_hnd, response_quota);
        if (CPA_STATUS_SUCCESS == status)
        {
            stat_total++;
        }

        /* Re-enable interrupts in case we are using epoll mode */
        if (ICP_RESP_TYPE_IRQ == ring_hnd->resp)
        {
            WRITE_CSR_INT_COL_EN(ring_hnd->bank_offset,
                                 ring_hnd->bank_data->interrupt_mask);
        }
    }
    ICP_MUTEX_UNLOCK(ring_hnd_first->user_lock);
    /* If any of the rings in the instance had data and was polled
     * return SUCCESS. */
    if (stat_total)
    {
        return CPA_STATUS_SUCCESS;
    }
    return CPA_STATUS_RETRY;
}

/*
 * This function allows the caller to check whether the response ring is empty
 * or not. The ring number to be polled is supplied by the user via the trans
 * handle for that ring. The trans_hnd is a pointer to an array of trans
 * handles.
 * This function will return RETRY if the ring is not empty.
 */
CpaStatus icp_adf_check_RespInstance(icp_comms_trans_handle *trans_hnd,
                                     Cpa32U num_transHandles)
{
    CpaBoolean is_ring_empty = CPA_TRUE;
    adf_dev_ring_handle_t *ring_hnd = NULL;
    Cpa32U i = 0;

    ICP_CHECK_FOR_NULL_PARAM(trans_hnd);

    for (i = 0; i < num_transHandles; i++)
    {
        ring_hnd = (adf_dev_ring_handle_t *)trans_hnd[i];
        if (!ring_hnd)
        {
            return CPA_STATUS_FAIL;
        }
        /* The ring is polled only when it is set as poll mode. */
        if (!ring_hnd->pollingMask)
        {
            continue;
        }

        is_ring_empty = adf_user_check_resp_ring(ring_hnd);

        if (CPA_FALSE == is_ring_empty)
        {
            return CPA_STATUS_RETRY;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * This function allows the user to check ring error bit status
 */
CpaStatus icp_adf_checkRingError(icp_comms_trans_handle *trans_hnd,
                                 Cpa32U num_transHandles)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    adf_dev_ring_handle_t *ring_hnd = NULL;
    adf_dev_ring_handle_t *ring_hnd_first = NULL;
    Cpa32U i = 0;
    Cpa32S res;

    ICP_CHECK_FOR_NULL_PARAM(trans_hnd);
    ring_hnd_first = (adf_dev_ring_handle_t *)trans_hnd[0];
    if (!ring_hnd_first)
    {
        return CPA_STATUS_SUCCESS;
    }

    ICP_MUTEX_LOCK(ring_hnd_first->user_lock);

    for (i = 0; i < num_transHandles; i++)
    {
        ring_hnd = (adf_dev_ring_handle_t *)trans_hnd[i];

        if (!ring_hnd->pollingMask)
        {
            continue;
        }

        res = adf_user_check_ring_error(ring_hnd);
        if (res == -EINTR || res == -EL2HLT)
        {
            status = CPA_STATUS_FAIL;
            break;
        }
    }
    ICP_MUTEX_UNLOCK(ring_hnd_first->user_lock);

    return status;
}

/*
 * Function initializes internal transport data
 */
CpaStatus adf_user_transport_init(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    Cpa32S x = 0;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    status = adf_proxy_populate_device_info(accel_dev);
    if (CPA_STATUS_SUCCESS != status)
    {
        return status;
    }

    banks = accel_dev->banks;
    for (i = 0; i < accel_dev->maxNumBanks; i++)
    {
        bank = &banks[i];
        bank->user_bank_lock = ICP_MALLOC_GEN(sizeof(ICP_MUTEX));
        if (!bank->user_bank_lock)
        {
            ADF_ERROR("Could not alloc memory for bank mutex\n");
            for (x = i - 1; x >= 0; x--)
            {
                bank = &banks[x];
                ICP_MUTEX_UNINIT(bank->user_bank_lock);
                ICP_FREE(bank->user_bank_lock);
            }
            adf_proxy_depopulate_device_info(accel_dev);
            return CPA_STATUS_FAIL;
        }
        if (OSAL_SUCCESS != ICP_MUTEX_INIT(bank->user_bank_lock))
        {
            ADF_ERROR("Mutex init failed for user_bank_lock\n");
            for (x = i; x >= 0; x--)
            {
                bank = &banks[x];
                ICP_MUTEX_UNINIT(bank->user_bank_lock);
                ICP_FREE(bank->user_bank_lock);
            }
            adf_proxy_depopulate_device_info(accel_dev);
            return CPA_STATUS_RESOURCE;
        }
    }
    return status;
}

/*
 * Function reinitializes internal transport data
 */
CpaStatus adf_user_transport_reinit(icp_accel_dev_t *accel_dev)
{
    Cpa32U i = 0;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;
    ICP_CHECK_FOR_NULL_PARAM(accel_dev);

    adf_proxy_repopulate_device_info(accel_dev);

    banks = accel_dev->banks;
    for (i = 0; i < accel_dev->maxNumBanks; i++)
    {
        bank = &banks[i];
        if (OSAL_SUCCESS != ICP_MUTEX_INIT(bank->user_bank_lock))
        {
            ADF_ERROR("Mutex init failed for user_bank_lock\n");
            return CPA_STATUS_RESOURCE;
        }
    }
    return CPA_STATUS_SUCCESS;
}

/*
 * Function deinitializes internal transport data
 */
CpaStatus adf_user_transport_exit(icp_accel_dev_t *accel_dev)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i = 0;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    banks = accel_dev->banks;
    for (i = 0; i < accel_dev->maxNumBanks; i++)
    {
        bank = &(banks)[i];
        if (NULL != bank->bundle)
        {
            adf_io_free_bundle(bank->bundle);
            bank->bundle = NULL;
        }

        if (bank->user_bank_lock)
        {
            ICP_MUTEX_UNINIT(bank->user_bank_lock);
            ICP_FREE(bank->user_bank_lock);
        }

        ICP_FREE(bank->rings);
    }
    adf_proxy_depopulate_device_info(accel_dev);
    return status;
}

/*
 * Function cleans internal transport data
 */
CpaStatus adf_user_transport_clean(icp_accel_dev_t *accel_dev)
{
    Cpa32U i = 0;
    Cpa32U device_id = 0;
    adf_dev_bank_handle_t *bank = NULL;
    adf_dev_bank_handle_t *banks = NULL;

    ICP_CHECK_FOR_NULL_PARAM(accel_dev);
    device_id = accel_dev->accelId;
    banks = accel_dev->banks;
    for (i = 0; i < accel_dev->maxNumBanks; i++)
    {
        bank = &(banks)[i];
        if (NULL != bank->bundle)
        {
            adf_io_free_bundle(bank->bundle);
            bank->bundle = NULL;
        }
        if ((bank->user_bank_lock) && (*(ICP_MUTEX *)(bank->user_bank_lock)))
        {
            ICP_MUTEX_UNINIT(bank->user_bank_lock);
        }
        ICP_FREE(bank->rings);
    }
    ICP_MEMSET(ringInflights[device_id],
               0,
               sizeof(Cpa32U) * (accel_dev->maxNumRingsPerBank >> 1) *
                   accel_dev->maxNumBanks);
    return CPA_STATUS_SUCCESS;
}

