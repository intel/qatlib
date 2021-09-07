/*
 * Do not modify, this file was taken from internal kernel sources.
 * To update, copy new version from kernel sources and:
 * 1. Add this comment
 * 2. Remove BUILD_BUG_ON from bottom of file
 * 3. Reformat using clang: clang-format -i -style=file
 * linux/user/src/vfio/adf_pfvf_msg.h
 */
/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only) */
/* Copyright(c) 2015 - 2020 Intel Corporation */
#ifndef ADF_PFVF_MSG_H
#define ADF_PFVF_MSG_H

/*
 * PF<->VF Gen2 Messaging format
 *
 * The PF has an array of 32-bit PF2VF registers, one for each VF. The
 * PF can access all these registers while each VF can access only the one
 * register associated with that particular VF.
 *
 * The register functionally is split into two parts:
 * The bottom half is for PF->VF messages. In particular when the first
 * bit of this register (bit 0) gets set an interrupt will be triggered
 * in the respective VF.
 * The top half is for VF->PF messages. In particular when the first bit
 * of this half of register (bit 16) gets set an interrupt will be triggered
 * in the PF.
 *
 * The remaining bits within this register are available to encode messages.
 * and implement a collision control mechanism to prevent concurrent use of
 * the PF2VF register by both the PF and VF.
 *
 *  31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16
 *  _______________________________________________
 * |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
 * +-----------------------------------------------+
 *  \___________________________/ \_________/ ^   ^
 *                ^                    ^      |   |
 *                |                    |      |   VF2PF Int
 *                |                    |      Message Origin
 *                |                    Message Type
 *                Message-specific Data/Reserved
 *
 *  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
 *  _______________________________________________
 * |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
 * +-----------------------------------------------+
 *  \___________________________/ \_________/ ^   ^
 *                ^                    ^      |   |
 *                |                    |      |   PF2VF Int
 *                |                    |      Message Origin
 *                |                    Message Type
 *                Message-specific Data/Reserved
 *
 * Message Origin (Should always be 1)
 * A legacy out-of-tree QAT driver allowed for a set of messages not supported
 * by this driver; these had a Message Origin of 0 and are ignored by this
 * driver.
 *
 * When a PF or VF attempts to send a message in the lower or upper 16 bits,
 * respectively, the other 16 bits are written to first with a defined
 * IN_USE_BY pattern as part of a collision control scheme (see adf_iov_putmsg).
 *
 *
 * PF<->VF Gen4 Messaging format
 *
 * Similarly to the gen2 messaging format, 32-bit long registers are used for
 * communication between PF and VFs. However, each VF and PF share a pair of
 * 32-bits register to avoid collisions: one for PV to VF messages and one
 * for VF to PF messages.
 *
 * Both the Interrupt bit and the Message Origin bit retain the same position
 * and meaning, although non-system messages are now deprecated and not
 * expected.
 *
 *  31 30              9  8  7  6  5  4  3  2  1  0
 *  _______________________________________________
 * |  |  |   . . .   |  |  |  |  |  |  |  |  |  |  |
 * +-----------------------------------------------+
 *  \_____________________/ \_______________/  ^  ^
 *             ^                     ^         |  |
 *             |                     |         |  PF/VF Int
 *             |                     |         Message Origin
 *             |                     Message Type
 *             Message-specific Data/Reserved
 *
 * For both formats, the message reception is acknowledged by lowering the
 * interrupt bit on the register where the message was sent.
 */

struct pfvf_message
{
    u32 data : 24;
    u32 type : 8;
};

/* PF->VF messages */
enum pf2vf_msgtype
{
    ADF_PF2VF_MSGTYPE_RESTARTING = 0x01,
    ADF_PF2VF_MSGTYPE_VERSION_RESP = 0x02,
    ADF_PF2VF_MSGTYPE_BLKMSG_RESP = 0x03,
    ADF_PF2VF_MSGTYPE_FATAL_ERROR = 0x04,
    /* Do not use messages which start from 0x10 to 1.x as 1.x only use *
     * 4 bits as message types. Hence they are only applicable to 2.0   */
    ADF_PF2VF_MSGTYPE_RP_RESET_RESP = 0x10,
};

/* VF->PF messages */
enum vf2pf_msgtype
{
    ADF_VF2PF_MSGTYPE_INIT = 0x03,
    ADF_VF2PF_MSGTYPE_SHUTDOWN = 0x04,
    ADF_VF2PF_MSGTYPE_VERSION_REQ = 0x05,
    ADF_VF2PF_MSGTYPE_COMPAT_VER_REQ = 0x06,
    ADF_VF2PF_MSGTYPE_LARGE_BLOCK_REQ = 0x07,
    ADF_VF2PF_MSGTYPE_MEDIUM_BLOCK_REQ = 0x08,
    ADF_VF2PF_MSGTYPE_SMALL_BLOCK_REQ = 0x09,
    /* Do not use messages which start from 0x10 to 1.x as 1.x only use *
     * 4 bits as message types. Hence they are only applicable to 2.0   */
    ADF_VF2PF_MSGTYPE_RP_RESET = 0x10,
};

/* VF/PF compatibility version. */
enum pfvf_compatibility_version
{
    /* Support for extended capabilities */
    ADF_PFVF_COMPAT_CAPABILITIES = 0x02,
    /* In-use pattern cleared by receiver */
    ADF_PFVF_COMPAT_FAST_ACK = 0x03,
    /* Ring to service mapping support for non-standard mappings */
    ADF_PFVF_COMPAT_RING_TO_SVC_MAP = 0x04,
    /* Reference to the latest version */
    ADF_PFVF_COMPAT_THIS_VERSION = 0x04,
};

/* PF->VF Version Request/Response */
struct pfvf_compat_message
{
    u32 version : 8;
    u32 compat : 2;
    u32 : 14;
    u32 type : 8;
};

enum pf2vf_compat_response
{
    ADF_PF2VF_VF_COMPATIBLE = 0x1,
    ADF_PF2VF_VF_INCOMPATIBLE = 0x2,
    ADF_PF2VF_VF_COMPAT_UNKNOWN = 0x3,
};

/* PF->VF Ring Reset Response */
struct pfvf_reset_rings_resp
{
    u32 result : 8;
    u32 : 16;
    u32 type : 8;
};

enum ring_reset_result
{
    RPRESET_SUCCESS = 0x1,
    RPRESET_NOT_SUPPORTED = 0x2,
    RPRESET_INVAL_BANK = 0x3,
    RPRESET_TIMEOUT = 0x4,
};

/* VF->PF Ring Reset Request */
struct pfvf_reset_rings_req
{
    u32 rings : 16;
    u32 : 8;
    u32 type : 8;
};

/* PF->VF Block Responses */
struct pf2vf_blkmsg_resp
{
    u32 blk_resp : 2;
    u32 data : 8;
    u32 : 14;
    u32 type : 8;
};

enum pf2vf_blkmsg_resp_type
{
    ADF_PF2VF_BLKMSG_RESP_TYPE_DATA = 0x00,
    ADF_PF2VF_BLKMSG_RESP_TYPE_CRC = 0x01,
    ADF_PF2VF_BLKMSG_RESP_TYPE_ERROR = 0x02,
};

/* PF->VF Block Error Code */
enum pf2vf_blkmsg_error
{
    ADF_PF2VF_INVALID_BLOCK_TYPE = 0x00,
    ADF_PF2VF_INVALID_BYTE_NUM_REQ = 0x01,
    ADF_PF2VF_PAYLOAD_TRUNCATED = 0x02,
    ADF_PF2VF_UNSPECIFIED_ERROR = 0x03,
};

/* VF->PF Block Requests */
struct vf2pf_blkmsg_req_small
{
    u32 blk_type : 4;
    u32 byte_num : 5;
    u32 crc : 1;
    u32 : 14;
    u32 type : 8;
};

struct vf2pf_blkmsg_req_medium
{
    u32 blk_type : 3;
    u32 byte_num : 6;
    u32 crc : 1;
    u32 : 14;
    u32 type : 8;
};

struct vf2pf_blkmsg_req_large
{
    u32 blk_type : 2;
    u32 byte_num : 7;
    u32 crc : 1;
    u32 : 14;
    u32 type : 8;
};

#define ADF_VF2PF_SMALL_PAYLOAD_SIZE 30
#define ADF_VF2PF_MEDIUM_PAYLOAD_SIZE 62
#define ADF_VF2PF_LARGE_PAYLOAD_SIZE 126

/* PF->VF Block Request Types
 *  0..15 - 32 byte message
 * 16..23 - 64 byte message
 * 24..27 - 128 byte message
 */
enum vf2pf_blkmsg_req_type
{
    ADF_VF2PF_BLKMSG_REQ_CAP_SUMMARY = 0x02,
    ADF_VF2PF_BLKMSG_REQ_RING_SVC_MAP = 0x03,
};

#define ADF_VF2PF_MIN_SMALL_MESSAGE_TYPE 0
#define ADF_VF2PF_MAX_SMALL_MESSAGE_TYPE 15
#define ADF_VF2PF_MIN_MEDIUM_MESSAGE_TYPE 16
#define ADF_VF2PF_MAX_MEDIUM_MESSAGE_TYPE 23
#define ADF_VF2PF_MIN_LARGE_MESSAGE_TYPE 24
#define ADF_VF2PF_MAX_LARGE_MESSAGE_TYPE 27

struct pfvf_blkmsg_header
{
    u8 version;
    u8 payload_size;
} __packed;

#define PFVF_BLKMSG_HEADER_SIZE (sizeof(struct pfvf_blkmsg_header))
#define PFVF_BLKMSG_MSG_SIZE(blkmsg)                                           \
    (PFVF_BLKMSG_HEADER_SIZE + blkmsg->hdr.payload_size)
#define PFVF_BLKMSG_PAYLOAD_SIZE(blkmsg)                                       \
    (sizeof(blkmsg) - PFVF_BLKMSG_HEADER_SIZE)

/* PF->VF Block message header bytes */
#define PFVF_BLKMSG_VERSION_BYTE 0
#define PFVF_BLKMSG_LEN_BYTE 1

/* PF/VF Capabilities message values */
enum blkmsg_capabilities_versions
{
    ADF_PFVF_CAPABILITIES_V1_VERSION = 0x01,
    ADF_PFVF_CAPABILITIES_V2_VERSION = 0x02,
    ADF_PFVF_CAPABILITIES_V3_VERSION = 0x03,
};

struct capabilities_v1
{
    struct pfvf_blkmsg_header hdr;
    u32 ext_dc_caps;
} __packed;

struct capabilities_v2
{
    struct pfvf_blkmsg_header hdr;
    u32 ext_dc_caps;
    u32 capabilities;
} __packed;

struct capabilities_v3
{
    struct pfvf_blkmsg_header hdr;
    u32 ext_dc_caps;
    u32 capabilities;
    u32 frequency;
} __packed;

/* PF/VF Ring to service mapping values */
enum blkmsg_ring_to_svc_versions
{
    ADF_PFVF_RING_TO_SVC_VERSION = 0x01,
};

struct ring_to_svc_map_v1
{
    struct pfvf_blkmsg_header hdr;
    u16 map;
} __packed;

#endif /* ADF_PFVF_MSG_H */
