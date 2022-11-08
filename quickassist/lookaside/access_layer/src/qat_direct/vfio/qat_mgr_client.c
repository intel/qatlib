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

/******************************************************************************
 * @file qat_mgr_client.c
 *
 * @description
 * Implements the qat manager client side. It provides functions to open
 * a connection to the manager and exchanging messages.
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "icp_platform.h"
#include "qat_log.h"
#include "qat_mgr.h"

#define QAT_ENV_POLICY "QAT_POLICY"
#define MAX_DEVS_NO_POLICY 6
#define MAX_DEVS_STATIC_CFG 256

static int qatmgr_sock = -1;
static OsalMutex qatmgr_mutex;

static int qatmgr_socket_open(void)
{
    struct sockaddr_un sockaddr;
    int ret = 0;

    if (qatmgr_sock > 0)
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to open socket\n");
        return -1;
    }

    qatmgr_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (qatmgr_sock < 0)
    {
        qat_log(LOG_LEVEL_ERROR, "Failed to create socket\n");
        return -1;
    }

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sun_family = AF_UNIX;
    ICP_STRLCPY(sockaddr.sun_path, QATMGR_SOCKET, sizeof(sockaddr.sun_path));

    ret = connect(qatmgr_sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (ret < 0)
    {
        qat_log(LOG_LEVEL_INFO, "Failed to connect to QAT manager\n");
        close(qatmgr_sock);
        qatmgr_sock = -1;
        return -1;
    }

    if (OSAL_SUCCESS != osalMutexInit(&qatmgr_mutex))
    {
        close(qatmgr_sock);
        qatmgr_sock = -1;
        return -1;
    }

    return 0;
}

static int adf_vfio_build_sconfig()
{
    int ret;
    char *env;
    long long devs = -1;
    unsigned n;
    struct qatmgr_dev_data dev_list[MAX_DEVS_STATIC_CFG];
    int i, j;
    char *fin;

    env = getenv(QAT_ENV_POLICY);
    if (env)
    {
        devs = strtoll(env, &fin, 10);
        if (errno == ERANGE || *fin != 0 || devs < 0 ||
            devs > MAX_DEVS_STATIC_CFG)
        {
            qat_log(LOG_LEVEL_ERROR, "Invalid environment value \"%s\"\n", env);
            return -EINVAL;
        }
    }

    /* If QAT_POLICY is not set, reserve all devices but then use only
     * the first MAX_DEVS_NO_POLICY
     * If QAT_POLICY is set to 0, enumerate all devices without reserving
     * them (qat_mgr_build_data might fail when devices are opened)
     * if QAT_POLICY is set to >0, reserve the first n devices */
    if (devs < 0)
        ret = qat_mgr_get_dev_list(&n, dev_list, MAX_DEVS_STATIC_CFG, 1);
    else if (devs == 0)
        ret = qat_mgr_get_dev_list(&n, dev_list, MAX_DEVS_STATIC_CFG, 0);
    else
        ret = qat_mgr_get_dev_list(&n, dev_list, devs, 1);

    if (ret)
        return ret;

    /* If no device is found return an error */
    if (n == 0)
    {
        qat_log(LOG_LEVEL_ERROR, "No device found\n");
        return -ENODEV;
    }

    /* Avoid using all devices if policy is not set */
    if (n > MAX_DEVS_NO_POLICY && devs < 0)
    {
        for (i = 0, j = 0; i < n; i++)
        {
            if (dev_list[i].group_fd > 0 && j < MAX_DEVS_NO_POLICY)
            {
                j++;
            }
            else if (dev_list[i].group_fd > 0)
            {
                close(dev_list[i].group_fd);
                dev_list[i].group_fd = -1;
            }
        }
        devs = j;
    }

    for (i = 0; i < n; i++)
    {
        qat_log(LOG_LEVEL_INFO,
                "Device %d, %X, %04x:%02x:%02x.%01x\n",
                i,
                dev_list[i].bdf,
                BDF_NODE(dev_list[i].bdf),
                BDF_BUS(dev_list[i].bdf),
                BDF_DEV(dev_list[i].bdf),
                BDF_FUN(dev_list[i].bdf));
    }

    if (devs < 0)
        devs = n;
    if ((ret = qat_mgr_build_data(dev_list, n, devs, 1)))
        return ret;

    return 0;
}

int qatmgr_open(void)
{
    int ret;

    ret = qatmgr_socket_open();
    if (ret)
    {
        qat_log(LOG_LEVEL_INFO, "Build static configuration\n");
        ret = adf_vfio_build_sconfig();
        if (!ret)
        {
            /** mutex isn't needed for static path but client use
             * common qat_mgr_lib code which is used also by qatmgr
             * where mutex is needed
             * so it should be initialized to make lib working properly
             **/
            ret = init_section_data_mutex();
        }
    }

    return ret;
}

int qatmgr_close(void)
{
    if (qatmgr_sock <= 0)
    {
        qat_log(LOG_LEVEL_DEBUG, "Cleanup static configuration\n");
        qat_mgr_cleanup_cfg();
        destroy_section_data_mutex();
        return 0;
    }

    close(qatmgr_sock);
    qatmgr_sock = -1;
    if (osalMutexDestroy(&qatmgr_mutex) == OSAL_FAIL)
        return -1;

    return 0;
}

int qatmgr_query(struct qatmgr_msg_req *req,
                 struct qatmgr_msg_rsp *rsp,
                 uint16_t type)
{
    int size_tx = 0;
    int size_rx = 0;
    ssize_t numchars;
    static int index = -1;
    pid_t tid = pthread_self();
    static char *section_name = NULL;

    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(req, -1);
    ICP_CHECK_FOR_NULL_PARAM_RET_CODE(rsp, -1);

    switch (type)
    {
        case QATMGR_MSGTYPE_SECTION_GET:
        case QATMGR_MSGTYPE_SECTION_PUT:
            size_tx = strnlen(req->name, sizeof(req->name) - 1) + 1;
            break;
        case QATMGR_MSGTYPE_NUM_DEVICES:
        case QATMGR_MSGTYPE_SECTION_INFO:
            size_tx = 0;
            break;
        case QATMGR_MSGTYPE_DEVICE_INFO:
        case QATMGR_MSGTYPE_DEVICE_ID:
        case QATMGR_MSGTYPE_VFIO_FILE:
            size_tx = sizeof(req->device_num);
            break;
        case QATMGR_MSGTYPE_INSTANCE_INFO:
        case QATMGR_MSGTYPE_INSTANCE_NAME:
            size_tx = sizeof(req->inst);
            break;
        default:
            qat_log(
                LOG_LEVEL_ERROR, "Unknown qat manager message type %d\n", type);
            return -1;
    }

    req->hdr.type = type;
    req->hdr.version = THIS_LIB_VERSION;
    req->hdr.len = sizeof(req->hdr) + size_tx;

    if (qatmgr_sock < 0)
        return handle_message(req, rsp, &section_name, tid, &index);

    osalMutexLock(&qatmgr_mutex, OSAL_WAIT_FOREVER);

    numchars = write(qatmgr_sock, req, req->hdr.len);
    if (numchars != req->hdr.len)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Failed write to qatmgr socket %lu, expected %u\n",
                numchars,
                req->hdr.len);
        osalMutexUnlock(&qatmgr_mutex);
        return -1;
    }

    numchars = read(qatmgr_sock, rsp, sizeof(*rsp));

    osalMutexUnlock(&qatmgr_mutex);

    if (rsp->hdr.version != THIS_LIB_VERSION)
    {
        char qatlib_ver_str[VER_STR_LEN];
        char qatmgr_ver_str[VER_STR_LEN];
        VER_STR(rsp->hdr.version, qatmgr_ver_str);
        VER_STR(THIS_LIB_VERSION, qatlib_ver_str);

        qat_log(
            LOG_LEVEL_ERROR,
            "This qatlib v%s received response from incompatible qatmgr v%s\n",
            qatlib_ver_str,
            qatmgr_ver_str);
        return -1;
    }
    if (rsp->hdr.type != type)
    {
        if (rsp->hdr.type == QATMGR_MSGTYPE_BAD)
            qat_log(LOG_LEVEL_ERROR,
                    "Bad qatmgr response to request %d, %s\n",
                    req->hdr.type,
                    rsp->error_text);
        else
            qat_log(LOG_LEVEL_ERROR,
                    "Unexpected qatmgr response %d to request %d\n",
                    rsp->hdr.type,
                    req->hdr.type);
        return -1;
    }

    switch (type)
    {
        case QATMGR_MSGTYPE_SECTION_GET:
        case QATMGR_MSGTYPE_INSTANCE_NAME:
            size_rx = strnlen(rsp->name, sizeof(rsp->name));
            break;
        case QATMGR_MSGTYPE_VFIO_FILE:
            size_rx = sizeof(rsp->vfio_file.fd) +
                      strnlen(rsp->vfio_file.name, sizeof(rsp->vfio_file.name));
            break;
        case QATMGR_MSGTYPE_SECTION_PUT:
            size_rx = 0;
            break;
        case QATMGR_MSGTYPE_NUM_DEVICES:
            size_rx = sizeof(rsp->num_devices);
            break;
        case QATMGR_MSGTYPE_DEVICE_INFO:
            size_rx = sizeof(rsp->device_info);
            break;
        case QATMGR_MSGTYPE_DEVICE_ID:
            size_rx = strnlen(rsp->device_id, sizeof(rsp->device_id));
            break;
        case QATMGR_MSGTYPE_SECTION_INFO:
            size_rx = sizeof(rsp->section_info);
            break;
        case QATMGR_MSGTYPE_INSTANCE_INFO:
            size_rx = sizeof(rsp->instance_info);
            break;
        default:
            qat_log(
                LOG_LEVEL_ERROR, "Unknown qat manager message type %d\n", type);
            return -1;
    }
    if (numchars < sizeof(rsp->hdr) + size_rx)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Failed to read from qatmgr socket, %lu expected %lu\n",
                numchars,
                sizeof(rsp->hdr) + size_rx);
        return -1;
    }

    return 0;
}
