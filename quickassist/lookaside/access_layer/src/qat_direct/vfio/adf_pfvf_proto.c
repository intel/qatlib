/***************************************************************************
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
 ***************************************************************************/

#include "adf_platform_common.h"
#include "adf_pfvf_proto.h"
#include "icp_platform.h"
#include "qat_log.h"

#ifndef BIT
#define BIT(n) (1 << n)
#endif

#define ADF_PFVF_INT BIT(0)
#define ADF_PFVF_MSGORIGIN_SYSTEM BIT(1)

#define ADF_PFVF_GEN4_MSGTYPE_SHIFT 2
#define ADF_PFVF_GEN4_MSGTYPE_MASK 0x3F
#define ADF_PFVF_GEN4_MSGDATA_SHIFT 8
#define ADF_PFVF_GEN4_MSGDATA_MASK 0xFFFFFF

#define ADF_PFVF_GEN4_PF2VF_CSR_ADDR_OFFSET 0x1008
#define ADF_PFVF_GEN4_VF2PF_CSR_ADDR_OFFSET 0x100C

/* How long to wait for far side to acknowledge receipt */
#define ADF_PFVF_MSG_ACK_DELAY_US 5
#define ADF_PFVF_MSG_ACK_MAX_RETRIES 500
/* If CSR is busy, how long to delay before retrying */
#define ADF_PFVF_MSG_COLL_RETRY_DELAY 5
#define ADF_PFVF_MSG_COLL_MAX_RETRIES 3
/* How long to wait for a response from the other side
 * and how often to retry when there is no response */
#define ADF_PFVF_MSG_RESP_TIMEOUT 100
#define ADF_PFVF_MSG_RESP_RETRIES 5

struct adf_pfvf_dev_data adf_init_pfvf_dev_data(void *pmiscbar_addr, int dev_id)
{
    struct adf_pfvf_dev_data dev = {0};

    if (pmiscbar_addr == NULL)
    {
        return dev;
    }

    dev.pmiscbar_addr = pmiscbar_addr;
    dev.dev_id = dev_id;
        dev.local_csr_offset = ADF_PFVF_GEN4_VF2PF_CSR_ADDR_OFFSET;
        dev.remote_csr_offset = ADF_PFVF_GEN4_PF2VF_CSR_ADDR_OFFSET;
        dev.type_shift = ADF_PFVF_GEN4_MSGTYPE_SHIFT;
        dev.data_shift = ADF_PFVF_GEN4_MSGDATA_SHIFT;
        dev.type_mask = ADF_PFVF_GEN4_MSGTYPE_MASK;
        dev.data_mask = ADF_PFVF_GEN4_MSGDATA_MASK;

    return dev;
}

static int adf_pfvf_msg_ack_timed_out(struct adf_pfvf_dev_data *dev,
                                      uint32_t *last,
                                      uint32_t int_bit)
{
    int count = 0;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    ICP_CHECK_FOR_NULL_PARAM(last);
    for (; count < ADF_PFVF_MSG_ACK_MAX_RETRIES; ++count)
    {
        usleep(ADF_PFVF_MSG_ACK_DELAY_US);
        *last = ICP_ADF_CSR_RD(dev->pmiscbar_addr, dev->local_csr_offset);
        if (!((*last) & int_bit))
            return 0;
    }

    return 1;
}


static int adf_pfvf_gen4_send(struct adf_pfvf_dev_data *dev,
                              struct pfvf_message msg)
{
    int ret = 0;
    uint32_t raw_msg;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    raw_msg = (msg.type << dev->type_shift) | (msg.data << dev->data_shift);
    raw_msg |= ADF_PFVF_INT | ADF_PFVF_MSGORIGIN_SYSTEM;
    ICP_ADF_CSR_WR(dev->pmiscbar_addr, dev->local_csr_offset, raw_msg);

    if (adf_pfvf_msg_ack_timed_out(dev, &raw_msg, ADF_PFVF_INT))
    {
        qat_log(LOG_LEVEL_INFO, "ACK not received from remote\n");
        ret = -EIO;
    }

    return ret;
}

int adf_send_vf2pf_msg(struct adf_pfvf_dev_data *dev, struct pfvf_message msg)
{

    if (dev == NULL)
    {
        qat_log(LOG_LEVEL_ERROR, "PF2VF dev is null\n");
        return -EINVAL;
    }

    if ((msg.type & dev->type_mask) != msg.type)
    {
        qat_log(LOG_LEVEL_ERROR,
                "PF2VF message type 0x%X out of range\n",
                msg.type);
        return -EINVAL;
    }

    if ((msg.data & dev->data_mask) != msg.data)
    {
        qat_log(LOG_LEVEL_ERROR,
                "PF2VF message data 0x%X out of range\n",
                msg.data);
        return -EINVAL;
    }

        return adf_pfvf_gen4_send(dev, msg);
}

struct pfvf_message adf_pfvf_gen4_recv(struct adf_pfvf_dev_data *dev)
{
    uint32_t val;
    struct pfvf_message msg = {0};

    if (dev == NULL)
    {
        return msg;
    }

    /* Read message from the CSR */
    val = ICP_ADF_CSR_RD(dev->pmiscbar_addr, dev->remote_csr_offset);

    /* We can now acknowledge the message reception by clearing the interrupt
     * bit */
    if (val & ADF_PFVF_INT)
    {
        ICP_ADF_CSR_WR(
            dev->pmiscbar_addr, dev->remote_csr_offset, val & ~ADF_PFVF_INT);

        msg.type = (val >> dev->type_shift) & dev->type_mask;
        msg.data = (val >> dev->data_shift) & dev->data_mask;
    }

    return msg;
}

struct pfvf_message adf_recv_pf2vf_msg(struct adf_pfvf_dev_data *dev)
{
        return adf_pfvf_gen4_recv(dev);
}

int adf_send_vf2pf_req(struct adf_pfvf_dev_data *dev,
                       struct pfvf_message req,
                       struct pfvf_message *resp)
{
    unsigned long timeout = ADF_PFVF_MSG_RESP_TIMEOUT;
    unsigned long retries = 0;
    int err;
    int response_received = 0;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    ICP_CHECK_FOR_NULL_PARAM(resp);
    do
    {
        err = adf_send_vf2pf_msg(dev, req);
        if (err)
        {
            qat_log(LOG_LEVEL_INFO, "Failed to send request msg to PF\n");
            return err;
        }

        usleep(timeout);

        *resp = adf_recv_pf2vf_msg(dev);
        if ((*resp).type != 0)
        {
            response_received = 1;
            return 0;
        }
    } while (!response_received && retries++ < ADF_PFVF_MSG_RESP_RETRIES);

    return -EIO;
}

STATIC int adf_vf2pf_blkmsg_data_req(struct adf_pfvf_dev_data *dev,
                                     uint8_t type,
                                     uint8_t byte,
                                     uint8_t *data,
                                     uint8_t is_crc)
{
    struct pfvf_message req = {0};
    struct pf2vf_blkmsg_resp resp;
    uint16_t max_payload_size;
    int err;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    ICP_CHECK_FOR_NULL_PARAM(data);
    /* Build the block message */
    if (type <= ADF_VF2PF_MAX_SMALL_MESSAGE_TYPE)
    {
        struct vf2pf_blkmsg_req_small *msg =
            (struct vf2pf_blkmsg_req_small *)&req;
        msg->type = ADF_VF2PF_MSGTYPE_SMALL_BLOCK_REQ;
        msg->blk_type = type;
        msg->byte_num = byte;
        msg->crc = is_crc;
        max_payload_size = ADF_VF2PF_SMALL_PAYLOAD_SIZE;
    }
    else if (type <= ADF_VF2PF_MAX_MEDIUM_MESSAGE_TYPE)
    {
        struct vf2pf_blkmsg_req_medium *msg =
            (struct vf2pf_blkmsg_req_medium *)&req;
        msg->type = ADF_VF2PF_MSGTYPE_MEDIUM_BLOCK_REQ;
        msg->blk_type = type - ADF_VF2PF_MIN_MEDIUM_MESSAGE_TYPE;
        msg->byte_num = byte;
        msg->crc = is_crc;
        max_payload_size = ADF_VF2PF_MEDIUM_PAYLOAD_SIZE;
    }
    else if (type <= ADF_VF2PF_MAX_LARGE_MESSAGE_TYPE)
    {
        struct vf2pf_blkmsg_req_large *msg =
            (struct vf2pf_blkmsg_req_large *)&req;
        msg->type = ADF_VF2PF_MSGTYPE_LARGE_BLOCK_REQ;
        msg->blk_type = type - ADF_VF2PF_MIN_LARGE_MESSAGE_TYPE;
        msg->byte_num = byte;
        msg->crc = is_crc;
        max_payload_size = ADF_VF2PF_LARGE_PAYLOAD_SIZE;
    }
    else
    {
        qat_log(LOG_LEVEL_ERROR, "Invalid message type %d\n", type);
        return -EINVAL;
    }

    if (byte >= max_payload_size + PFVF_BLKMSG_HEADER_SIZE)
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid byte index %d for message type %d\n",
                byte,
                type);
        return -EINVAL;
    }

    err = adf_send_vf2pf_req(dev, req, (struct pfvf_message *)&resp);
    if (err)
        return err;

    if (resp.blk_resp == ADF_PF2VF_BLKMSG_RESP_TYPE_ERROR)
    {
        qat_log(LOG_LEVEL_ERROR, "Error in blk message response\n");
        return -EIO;
    }

    *data = resp.data;
    return 0;
}

static int adf_vf2pf_blkmsg_get_byte(struct adf_pfvf_dev_data *dev,
                                     uint8_t type,
                                     uint8_t index,
                                     uint8_t *data)
{
    return adf_vf2pf_blkmsg_data_req(dev, type, index, data, 0);
}

static int adf_vf2pf_blkmsg_get_crc(struct adf_pfvf_dev_data *dev,
                                    uint8_t type,
                                    uint8_t bytes,
                                    uint8_t *crc)
{
    return adf_vf2pf_blkmsg_data_req(dev, type, bytes - 1, crc, 1);
}

/* CRC Calculation */
#define ADF_CRC8_INIT_VALUE 0xFF

static const unsigned char pfvf_crc8_table[] = {
    0x00, 0x97, 0xB9, 0x2E, 0xE5, 0x72, 0x5C, 0xCB, 0x5D, 0xCA, 0xE4, 0x73,
    0xB8, 0x2F, 0x01, 0x96, 0xBA, 0x2D, 0x03, 0x94, 0x5F, 0xC8, 0xE6, 0x71,
    0xE7, 0x70, 0x5E, 0xC9, 0x02, 0x95, 0xBB, 0x2C, 0xE3, 0x74, 0x5A, 0xCD,
    0x06, 0x91, 0xBF, 0x28, 0xBE, 0x29, 0x07, 0x90, 0x5B, 0xCC, 0xE2, 0x75,
    0x59, 0xCE, 0xE0, 0x77, 0xBC, 0x2B, 0x05, 0x92, 0x04, 0x93, 0xBD, 0x2A,
    0xE1, 0x76, 0x58, 0xCF, 0x51, 0xC6, 0xE8, 0x7F, 0xB4, 0x23, 0x0D, 0x9A,
    0x0C, 0x9B, 0xB5, 0x22, 0xE9, 0x7E, 0x50, 0xC7, 0xEB, 0x7C, 0x52, 0xC5,
    0x0E, 0x99, 0xB7, 0x20, 0xB6, 0x21, 0x0F, 0x98, 0x53, 0xC4, 0xEA, 0x7D,
    0xB2, 0x25, 0x0B, 0x9C, 0x57, 0xC0, 0xEE, 0x79, 0xEF, 0x78, 0x56, 0xC1,
    0x0A, 0x9D, 0xB3, 0x24, 0x08, 0x9F, 0xB1, 0x26, 0xED, 0x7A, 0x54, 0xC3,
    0x55, 0xC2, 0xEC, 0x7B, 0xB0, 0x27, 0x09, 0x9E, 0xA2, 0x35, 0x1B, 0x8C,
    0x47, 0xD0, 0xFE, 0x69, 0xFF, 0x68, 0x46, 0xD1, 0x1A, 0x8D, 0xA3, 0x34,
    0x18, 0x8F, 0xA1, 0x36, 0xFD, 0x6A, 0x44, 0xD3, 0x45, 0xD2, 0xFC, 0x6B,
    0xA0, 0x37, 0x19, 0x8E, 0x41, 0xD6, 0xF8, 0x6F, 0xA4, 0x33, 0x1D, 0x8A,
    0x1C, 0x8B, 0xA5, 0x32, 0xF9, 0x6E, 0x40, 0xD7, 0xFB, 0x6C, 0x42, 0xD5,
    0x1E, 0x89, 0xA7, 0x30, 0xA6, 0x31, 0x1F, 0x88, 0x43, 0xD4, 0xFA, 0x6D,
    0xF3, 0x64, 0x4A, 0xDD, 0x16, 0x81, 0xAF, 0x38, 0xAE, 0x39, 0x17, 0x80,
    0x4B, 0xDC, 0xF2, 0x65, 0x49, 0xDE, 0xF0, 0x67, 0xAC, 0x3B, 0x15, 0x82,
    0x14, 0x83, 0xAD, 0x3A, 0xF1, 0x66, 0x48, 0xDF, 0x10, 0x87, 0xA9, 0x3E,
    0xF5, 0x62, 0x4C, 0xDB, 0x4D, 0xDA, 0xF4, 0x63, 0xA8, 0x3F, 0x11, 0x86,
    0xAA, 0x3D, 0x13, 0x84, 0x4F, 0xD8, 0xF6, 0x61, 0xF7, 0x60, 0x4E, 0xD9,
    0x12, 0x85, 0xAB, 0x3C};

static uint8_t adf_pfvf_crc(uint8_t start_crc, uint8_t *buf, uint8_t len)
{
    uint8_t crc = start_crc;
    
    ICP_CHECK_FOR_NULL_PARAM(buf);

    while (len-- > 0)
        crc = pfvf_crc8_table[(crc ^ *buf++) & 0xff];

    return crc;
}

uint8_t adf_pfvf_calc_blkmsg_crc(uint8_t *buf, uint8_t buf_len)
{
    return adf_pfvf_crc(ADF_CRC8_INIT_VALUE, buf, buf_len);
}

int adf_send_vf2pf_blkmsg_req(struct adf_pfvf_dev_data *dev,
                              uint8_t type,
                              uint8_t *buffer,
                              uint16_t *buffer_len)
{
    uint8_t remote_crc;
    uint8_t local_crc;
    uint16_t index;
    uint16_t msg_len;
    int ret;

    ICP_CHECK_FOR_NULL_PARAM(dev);
    ICP_CHECK_FOR_NULL_PARAM(buffer);
    ICP_CHECK_FOR_NULL_PARAM(buffer_len);

    if (type > ADF_VF2PF_MAX_LARGE_MESSAGE_TYPE)
    {
        qat_log(LOG_LEVEL_ERROR, "Invalid message type %d\n", type);
        return -EINVAL;
    }

    if (*buffer_len < PFVF_BLKMSG_HEADER_SIZE)
    {
        qat_log(LOG_LEVEL_ERROR, "Buffer size too small for a block message\n");
        return -EINVAL;
    }

    ret = adf_vf2pf_blkmsg_get_byte(
        dev, type, PFVF_BLKMSG_VERSION_BYTE, &buffer[PFVF_BLKMSG_VERSION_BYTE]);
    if (ret)
        return ret;

    if (0 == buffer[PFVF_BLKMSG_VERSION_BYTE])
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid version 0 received for block request %u\n",
                type);
        return -EFAULT;
    }

    ret = adf_vf2pf_blkmsg_get_byte(
        dev, type, PFVF_BLKMSG_LEN_BYTE, &buffer[PFVF_BLKMSG_LEN_BYTE]);
    if (ret)
        return ret;

    if (0 == buffer[PFVF_BLKMSG_LEN_BYTE])
    {
        qat_log(LOG_LEVEL_ERROR,
                "Invalid size 0 received for block request %u\n",
                type);
        return -EFAULT;
    }

    /* We need to pick the minimum since there is no way to request a
     * specific version. As a consequence any scenario is possible:
     * - PF has a newer (longer) version which doesn't fit in the buffer
     * - VF expects a newer (longer) version, so we must not ask for
     *   bytes in excess
     * - PF and VF share the same version, no problem
     */

    msg_len = PFVF_BLKMSG_HEADER_SIZE + buffer[PFVF_BLKMSG_LEN_BYTE];
    if (*buffer_len < msg_len)
    {
        qat_log(LOG_LEVEL_INFO,
                "Truncating block type %d response from %d to %d bytes\n",
                type,
                msg_len,
                *buffer_len);
        msg_len = *buffer_len;
    }

    /* Get the payload */
    for (index = PFVF_BLKMSG_HEADER_SIZE; index < msg_len; index++)
    {
        ret = adf_vf2pf_blkmsg_get_byte(dev, type, index, &buffer[index]);
        if (ret)
            return ret;
    }

    ret = adf_vf2pf_blkmsg_get_crc(dev, type, msg_len, &remote_crc);
    if (ret)
        return ret;

    local_crc = adf_pfvf_calc_blkmsg_crc(buffer, msg_len);

    if (local_crc != remote_crc)
    {
        qat_log(LOG_LEVEL_ERROR,
                "CRC error on msg type %d. Local %02X, remote %02X\n",
                type,
                local_crc,
                remote_crc);
        return -EIO;
    }

    *buffer_len = msg_len;
    return 0;
}
