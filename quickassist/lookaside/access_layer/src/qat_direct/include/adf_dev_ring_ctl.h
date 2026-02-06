/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef ADF_DEV_RING_CTL_H
#define ADF_DEV_RING_CTL_H

#define OSAL_DEV_DRV_COMMON_H

#include <icp_accel_devices.h>
#include <icp_adf_init.h>
#include <icp_adf_transport.h>

#define EMPTY_RING_SIG_BYTE 0x7f
#define EMPTY_RING_SIG_WORD 0x7f7f7f7f

#define BYTESPERWORD 4

typedef struct adf_dev_bank_handle_s
{
    uint32_t accel_num;
    uint32_t bank_number;
    unsigned int bank_offset; /* offset from base addr (bank_sz * bank_nu) */
    uint32_t interrupt_mask;
    uint32_t pollingMask;
    OsalMutex user_bank_lock;

    uint16_t tx_rings_mask;
    uint16_t ring_mask; /* enabled rings */
    uint32_t *csr_addr;
    uint32_t *csr_addr_shadow;
    void *bundle;
    struct adf_dev_ring_handle_s **rings; /* ring handle for this banks */
    uint32_t num_rings_per_bank;          /* maximum number of rings per bank */
    int refs;                             /* reference count */
} adf_dev_bank_handle_t;

typedef struct adf_dev_ring_handle_s
{
    icp_accel_dev_t *accel_dev;
    icp_transport_type trans_type;
    char *service_name;
    uint32_t service_name_len;
    char *section_name;
    uint32_t section_name_len;
    uint32_t accel_num;
    uint32_t bank_num;
    uint32_t bank_offset; /* offset from base addr (bank_sz * bank_nu) */
    uint32_t ring_num;
    uint32_t ring_size;
    uint32_t message_size;
    uint64_t send_seq; /* packet sequence number */
    adf_ring_queue_mode_t ringMode;

    icp_adf_ringInfoService_t info;
    icp_trans_callback callback;
    icp_resp_deliv_method resp;

    /* Result Parameters */
    void *ring_virt_addr;
    uint64_t ring_phys_base_addr;
    uint32_t interrupt_user_mask;
    uint32_t pollingMask;
    uint32_t is_wireless : 1;
    adf_dev_bank_handle_t *bank_data;

    /* userspace shadow values */
    OsalMutex user_lock;
    uint32_t head;
    uint32_t tail;
    uint32_t space;
    uint32_t modulo;
    uint32_t ringResponseQuota;
    int64_t pollingInProgress;
    Cpa32U *in_flight;
    uint32_t max_requests_inflight;
    uint32_t coal_write_count;
    uint32_t min_resps_per_head_write;
    /* the offset  of the actual csr tail */
    uint32_t csrTailOffset;

    uint32_t *csr_addr;
} adf_dev_ring_handle_t;

#define IS_RING_IN_WQ_MODE(ring) ((ring)->ringMode == ADF_RING_WQ_MODE)

#endif /* ADF_DEV_RING_CTL_H */
