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
 * @file dc_header_footer_lz4.c
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the Data Compression header and footer operations for
 *      LZ4 algorithm.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#include "cpa.h"
#include "lac_common.h"
#include "dc_session.h"
#include "dc_header_footer_lz4.h"
#include "dc_xxhash32.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */

#pragma pack(push, 1)
typedef struct
{
    Cpa8U dict_id : 1; /* dictionary present */
    Cpa8U resv1 : 1;
    Cpa8U cnt_cksum : 1; /* content checksum present */
    Cpa8U cnt_size : 1;  /* content size present */
    Cpa8U blk_cksum : 1; /* block checksum present */
    Cpa8U blk_indep : 1; /* block linked/independent */
    Cpa8U version : 2;   /* version */
} lz4_hdr_flag_byte;

typedef struct
{
    Cpa32U magic; /* LZ4 magic number */
    union {
        lz4_hdr_flag_byte bit_field;
        Cpa8U addr;
    };
    Cpa8U resv2 : 4;
    Cpa8U blk_maxsize : 3; /* max block size */
    Cpa8U resv3 : 1;
    Cpa8U hdr_cksum; /* header checksum */
} lz4_hdr_t;

typedef struct
{
    Cpa32U end_mark;  /* LZ4 end mark */
    Cpa32U cnt_cksum; /* content checksum */
} lz4_footer_t;
#pragma pack(pop)

/* If compilation fails on below lines structures: lz4_hdr_t or lz4_footer_t
 * have invalid size.
 */
typedef Cpa8U static_assert_lz4_header_size
    [(sizeof(lz4_hdr_t) == DC_LZ4_HEADER_SIZE) ? 1 : -1];
typedef Cpa8U static_assert_lz4_footer_size
    [(sizeof(lz4_footer_t) == DC_LZ4_FOOTER_SIZE) ? 1 : -1];

CpaStatus dc_lz4_generate_header(const CpaFlatBuffer *dest_buff,
                                 const CpaDcCompLZ4BlockMaxSize max_block_size,
                                 const CpaBoolean block_indep,
                                 Cpa32U *count)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    lz4_hdr_t *header_ptr;

    /* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_PARAM_RANGE(block_indep, 0, 2);
    LAC_CHECK_NULL_PARAM(dest_buff);
    LAC_CHECK_NULL_PARAM(dest_buff->pData);
    LAC_CHECK_NULL_PARAM(count);
    LAC_CHECK_PARAM_RANGE(max_block_size,
                          CPA_DC_LZ4_MAX_BLOCK_SIZE_64K,
                          CPA_DC_LZ4_MAX_BLOCK_SIZE_4M + 1);
    if (dest_buff->dataLenInBytes < DC_LZ4_HEADER_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                              "is too small");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    osalMemSet(dest_buff->pData, 0, DC_LZ4_HEADER_SIZE);
    header_ptr = (lz4_hdr_t *)dest_buff->pData;

    header_ptr->magic = DC_LZ4_FH_ID;
    header_ptr->bit_field.version = DC_LZ4_FH_FLG_VERSION;
    header_ptr->bit_field.blk_indep = block_indep;
    header_ptr->bit_field.cnt_cksum = 1;
    header_ptr->blk_maxsize = max_block_size + DC_LZ4_FH_MAX_BLK_SIZE_ENUM_MIN;

    status = dcXxhash32Lz4HdrChecksum(
        &header_ptr->addr,
        (Cpa32U)(&header_ptr->hdr_cksum - &header_ptr->addr),
        &header_ptr->hdr_cksum);

    if (status != CPA_STATUS_SUCCESS)
        return CPA_STATUS_FAIL;

    *count = (Cpa32U)DC_LZ4_HEADER_SIZE;

    return CPA_STATUS_SUCCESS;
}

CpaStatus dc_lz4_generate_footer(const CpaFlatBuffer *dest_buff,
                                 const CpaDcRqResults *pRes)
{
    lz4_footer_t *footer_ptr;

    /* Check parameters */
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(dest_buff);
    LAC_CHECK_NULL_PARAM(dest_buff->pData);
    LAC_CHECK_NULL_PARAM(pRes);
    if (dest_buff->dataLenInBytes < DC_LZ4_FOOTER_SIZE)
    {
        LAC_INVALID_PARAM_LOG("The dataLenInBytes of the dest buffer "
                              "is too small for LZ4 footer");
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    osalMemSet(dest_buff->pData, 0, DC_LZ4_FOOTER_SIZE);
    footer_ptr = (lz4_footer_t *)dest_buff->pData;

    footer_ptr->end_mark = DC_LZ4_FF_END_MARK;
    footer_ptr->cnt_cksum = pRes->checksum;

    return CPA_STATUS_SUCCESS;
}
