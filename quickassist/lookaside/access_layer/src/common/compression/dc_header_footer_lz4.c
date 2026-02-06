/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
