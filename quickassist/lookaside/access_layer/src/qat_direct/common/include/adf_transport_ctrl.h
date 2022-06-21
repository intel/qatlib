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
 * @file adf_transport.h
 *
 * @description
 *      File contains simple interface for components to get
 *      a handle for appropriate transport type.
 *
 *****************************************************************************/
#ifndef ADF_TRANSPORT_CTRL_H
#define ADF_TRANSPORT_CTRL_H

#include "icp_adf_transport.h"

/* Magic number used to indicated that this message is read, and the
 * status is empty now
 */
#define EMPTY_RING_ENTRY_SIG (0x7F7F7F7F)

/*
 * Structure of a dyn instance handle
 */
typedef struct icp_dyn_instance_handle_s
{
    Cpa32U instance_id;
    adf_service_type_t stype;
    struct icp_dyn_instance_handle_s *pNext;
    struct icp_dyn_instance_handle_s *pPrev;
} icp_dyn_instance_handle_t;

/*
 * Structure of a transport handle
 */
typedef struct icp_trans_handle_s
{
    /* Acceleration Handle for this transport */
    icp_accel_dev_t *accel_dev;

    /* Handle Identifier */
    icp_trans_identifier handle_id;

    /* Transport Type */
    icp_transport_type trans_type;

    /* Put a message onto the transport and wait for a response.
     * Note: Not all transports support sync messages.*/

    CpaStatus (*put_msg_sync)(struct icp_trans_handle_s *trans_handle,
                              Cpa32U *inBuf,
                              Cpa32U *outBuf,
                              Cpa32U buffsLen);

    /* Put a message onto the transport */
    CpaStatus (*put_msg)(struct icp_trans_handle_s *trans_handle,
                         Cpa32U *inBuf,
                         Cpa32U bufLen);

    /* register a callback for notification when something is available */
    CpaStatus (*reg_callback)(struct icp_trans_handle_s *trans_handle,
                              icp_trans_callback callback);

    /* notify handle to notify subscribed callbacks of messages */
    CpaStatus (*notify)(struct icp_trans_handle_s *trans_handle);

    /* notify handle for polling to notify subscribed callbacks of messages */
    CpaStatus (*polling_notify)(struct icp_trans_handle_s *trans_handle,
                                Cpa32U response_quota);
    /* Transport specific data to ease processing */
    void *trans_data;

    CpaBoolean is_dyn;

    struct icp_trans_handle_s *pNext;
    struct icp_trans_handle_s *pPrev;
} icp_trans_handle;

/*
 * Structure for dynamic instance resource management
 */
typedef struct adf_instancemgr_s
{
    Cpa32U serv_type;
    ICP_MUTEX instance_lock;
    Cpa32U max_instance;
    Cpa32U *instances;
    Cpa32U last_found;
    Cpa32U avail;
} adf_instancemgr_t;

/*
 * Function Pointer for creating the transport handle
 */
typedef CpaStatus (*mgr_create_handle)(icp_accel_dev_t *accel_dev,
                                       const char *section,
                                       Cpa32U accel_nr,
                                       Cpa32U bank_nr,
                                       icp_trans_handle **trans_handle,
                                       icp_adf_ringInfoService_t info,
                                       const char *service_name,
                                       const Cpa32U size,
                                       const Cpa32U msg_size,
                                       Cpa32U flags);

/*
 * Function Pointer for releasing the transport handle
 */
typedef CpaStatus (*mgr_release_handle)(icp_trans_handle *trans_handle);

/*
 * Function Pointer for finding an existing transport handle
 */
typedef CpaStatus (*mgr_find_handle)(icp_accel_dev_t *accel_dev,
                                     icp_trans_identifier trans_id,
                                     icp_trans_handle **trans_handle);

/*
 * Function Pointer for returning the ring number for a transport handle
 */
typedef CpaStatus (*mgr_get_ring_num)(icp_trans_handle *trans_handle,
                                      Cpa32U *ringNum);
/*
 * Struct representing a transport manager
 */
typedef struct icp_trans_mgr_s
{
    icp_transport_type trans_type;
    mgr_create_handle create_handle;
    mgr_release_handle release_handle;
    mgr_find_handle find_handle;
    mgr_get_ring_num get_ring_num;
    void *privData;
    struct icp_trans_mgr_s *pPrev;
    struct icp_trans_mgr_s *pNext;
} icp_trans_mgr;

/*
 * Register the ring manager with the ring factory
 */
CpaStatus adf_trans_registerTransMgr(icp_trans_mgr *trans_mgr);

/*
 * Remove the ring manager from the ring factory
 */
CpaStatus adf_trans_deregisterTransMgr(icp_trans_mgr *trans_mgr);

/*
 * Initialize dynamic instance pool
 */
CpaStatus adf_trans_initDynInstancePool(icp_accel_dev_t *accel_dev,
                                        Cpa32U crypto_num,
                                        Cpa32U compress_num);

/*
 * Destroy dynamic instance pool
 */
CpaStatus adf_trans_destroyDynInstancePool(icp_accel_dev_t *accel_dev);

/*
 * Get an availble dynamic instance from the dynamic instance pool
 */
CpaStatus adf_trans_getDynInstance(icp_accel_dev_t *accel_dev,
                                   adf_service_type_t stype,
                                   Cpa32U *pinstance_id);

/*
 * Put back a dynamic instance into the dynamic instance pool
 */
CpaStatus adf_trans_putDynInstance(icp_accel_dev_t *accel_dev,
                                   adf_service_type_t stype,
                                   Cpa32U instance_id);

/*
 * Get the number of the availeble dynamic instances
 * in the dynamic instance pool
 */
CpaStatus adf_trans_getNumAvailDynInstance(icp_accel_dev_t *accel_dev,
                                           adf_service_type_t stype,
                                           Cpa32U *num);

#endif /* ADF_TRANSPORT_CTRL_H */
