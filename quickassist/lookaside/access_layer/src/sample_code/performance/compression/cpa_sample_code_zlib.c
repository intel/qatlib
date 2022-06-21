/***************************************************************************
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
 * @file cpa_sample_code_zlib.c
 *
 *
 * @ingroup sample_code
 *
 * @description
 *    This is sample code that uses zlib to compress/decompress data.
 *****************************************************************************/

#include "cpa_dc.h"
#include "cpa_sample_code_utils_common.h"
#include "cpa_sample_code_dc_utils.h"
#ifdef USER_SPACE
#include "zlib.h"
#else
#include <linux/zlib.h>
#include <linux/vmalloc.h>
#endif
#include "qat_compression_zlib.h"

#ifdef USER_SPACE
CpaStatus deflate_init(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    int ret = 0;
    stream->zalloc = (alloc_func)0;
    stream->zfree = (free_func)0;
    stream->opaque = (voidpf)0;
    stream->next_in = Z_NULL;
    stream->next_out = Z_NULL;
    stream->avail_in = stream->avail_out = stream->total_out = 0;
    stream->adler = 0;

    ret = deflateInit2(stream,
                       DEFLATE_DEF_LEVEL,
                       Z_DEFLATED,
                       -DEFLATE_DEF_WINBITS,
                       DEFLATE_DEF_MEMLEVEL,
                       Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
    {
        PRINT_ERR("Error in deflateInit2\n");
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}

/*Compress Date on a zlib stream*/
CpaStatus deflate_compress(struct z_stream_s *stream,
                           const Cpa8U *src,
                           Cpa32U slen,
                           Cpa8U *dst,
                           Cpa32U dlen,
                           int deflate_type)
{
#ifdef USE_ZLIB
    int ret = 0;

    stream->next_in = (Cpa8U *)src;
    stream->avail_in = slen;
    stream->next_out = (Cpa8U *)dst;
    stream->avail_out = dlen;
    ret = deflate(stream, deflate_type);
    if (ret != Z_STREAM_END && ret != Z_OK)
    {
        PRINT_ERR("Error in zlib_deflate, ret = %d\n", ret);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}

CpaStatus inflate_init(z_stream *stream, CpaDcSessionState sessState)
{
#ifdef USE_ZLIB
    int ret = 0;
    stream->zalloc = (alloc_func)0;
    stream->zfree = (free_func)0;
    stream->opaque = (voidpf)0;
    stream->next_in = Z_NULL;
    stream->next_out = Z_NULL;
    stream->avail_in = stream->avail_out = stream->total_out = 0;
    stream->adler = 0;

    ret = inflateInit2(stream, -DEFLATE_DEF_WINBITS);
    if (ret != Z_OK)
    {
        PRINT_ERR("Error in inflateInit2, ret = %d\n", ret);
        return CPA_STATUS_FAIL;
    }
    if (sessState == CPA_DC_STATEFUL)
    {
#if ZLIB_VERNUM >= 0x1234
        ret = inflateReset2(stream, -DEFLATE_DEF_WINBITS);
#else
        ret = inflateReset(stream);
#endif
        if (ret != Z_OK)
        {
            PRINT_ERR("Error in inflateReset\n");
            return CPA_STATUS_FAIL;
        }
    }
#endif
    return CPA_STATUS_SUCCESS;
}

CpaStatus inflate_decompress(z_stream *stream,
                             const Cpa8U *src,
                             Cpa32U slen,
                             Cpa8U *dst,
                             Cpa32U dlen,
                             CpaDcSessionState sessState)
{
#ifdef USE_ZLIB
    int ret = 0;
    int flushFlag = Z_SYNC_FLUSH;

    if (sessState == CPA_DC_STATELESS)
    {
        flushFlag = Z_FULL_FLUSH;
    }

    stream->next_in = (Cpa8U *)src;
    stream->avail_in = slen;
    stream->next_out = (Cpa8U *)dst;
    stream->avail_out = dlen;

    ret = inflate(stream, flushFlag);
    if (ret != Z_OK && ret != Z_STREAM_END)
    {
        PRINT_ERR("Error in inflate, ret = %d\n", ret);
        PRINT_ERR("stream msg = %s\n", stream->msg);
        PRINT_ERR("stream adler = %u\n", (unsigned int)stream->adler);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}

/*close zlib stream*/
void deflate_destroy(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    deflateEnd(stream);
#endif
}

/*close zlib stream*/
void inflate_destroy(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    inflateEnd(stream);
#endif
}
#endif
#ifdef KERNEL_SPACE
/* initialize a zlib stream*/
CpaStatus deflate_init(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
    stream->workspace =
        vmalloc(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL));
#else
    stream->workspace = vmalloc(zlib_deflate_workspacesize());
#endif
    if (NULL == stream->workspace)
    {
        PRINT_ERR("Could not allocate zlib workspace memory\n");
        return CPA_STATUS_FAIL;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
    memset(stream->workspace,
           0,
           zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL));
#else
    memset(stream->workspace, 0, zlib_deflate_workspacesize());
#endif
    ret = zlib_deflateInit2(stream,
                            DEFLATE_DEF_LEVEL,
                            Z_DEFLATED,
                            -DEFLATE_DEF_WINBITS,
                            DEFLATE_DEF_MEMLEVEL,
                            Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
    {
        PRINT_ERR("Error in zlib_deflateInit2\n");
        vfree(stream->workspace);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(deflate_init);

/*Compress Date on a zlib stream*/
CpaStatus deflate_compress(struct z_stream_s *stream,
                           const Cpa8U *src,
                           Cpa32U slen,
                           Cpa8U *dst,
                           Cpa32U dlen,
                           int inflate_type)
{
#ifdef USE_ZLIB
    int ret = 0;

    stream->next_in = (Cpa8U *)src;
    stream->avail_in = slen;
    stream->next_out = (Cpa8U *)dst;
    stream->avail_out = dlen;

    ret = zlib_deflate(stream, inflate_type);
    if (ret != Z_STREAM_END && ret != Z_OK)
    {
        PRINT_ERR("Error in zlib_deflate, ret = %d\n", ret);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(deflate_compress);

/*close zlib stream*/
void deflate_destroy(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    zlib_deflateEnd(stream);
    vfree(stream->workspace);
#endif
}
EXPORT_SYMBOL(deflate_destroy);

CpaStatus inflate_init(z_stream *stream, CpaDcSessionState sessState)
{
#ifdef USE_ZLIB
    int ret = 0;

    stream->workspace = vmalloc(zlib_inflate_workspacesize());
    if (NULL == stream->workspace)
    {
        PRINT_ERR("Could not allocate zlib workspace memory\n");
        return CPA_STATUS_FAIL;
    }

    memset(stream->workspace, 0, zlib_inflate_workspacesize());
    ret = zlib_inflateInit2(stream, -MAX_WBITS);
    if (ret != Z_OK)
    {
        PRINT_ERR("Error in zlib_inflateInit2, ret = %d\n", ret);
        return CPA_STATUS_FAIL;
    }
    if (sessState == CPA_DC_STATEFUL)
    {
        ret = zlib_inflateReset(stream);
        if (ret != Z_OK)
        {
            PRINT_ERR("Error in zlib_inflateReset, ret = %d\n", ret);
            return CPA_STATUS_FAIL;
        }
    }
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(inflate_init);

CpaStatus inflate_decompress(z_stream *stream,
                             const Cpa8U *src,
                             Cpa32U slen,
                             Cpa8U *dst,
                             Cpa32U dlen,
                             CpaDcSessionState sessState)
{
#ifdef USE_ZLIB
    int ret = 0;
    int flushFlag = Z_SYNC_FLUSH;

    if (sessState == CPA_DC_STATELESS)
    {
        flushFlag = Z_FULL_FLUSH;
    }

    stream->next_in = (Cpa8U *)src;
    stream->avail_in = slen;
    stream->next_out = (Cpa8U *)dst;
    stream->avail_out = dlen;

    ret = zlib_inflate(stream, flushFlag);
    if (ret != Z_OK && ret != Z_STREAM_END)
    {
        PRINT_ERR("Error in zlib_inflate, ret = %d\n", ret);
        PRINT_ERR("stream msg = %s\n", stream->msg);
        PRINT_ERR("stream adler = %u\n", (unsigned int)stream->adler);
        return CPA_STATUS_FAIL;
    }
#endif
    return CPA_STATUS_SUCCESS;
}
EXPORT_SYMBOL(inflate_decompress);

/*close zlib stream*/
void inflate_destroy(struct z_stream_s *stream)
{
#ifdef USE_ZLIB
    zlib_inflateEnd(stream);
    if (stream->workspace != NULL)
    {
        vfree(stream->workspace);
    }
#endif
}
EXPORT_SYMBOL(inflate_destroy);
#endif
