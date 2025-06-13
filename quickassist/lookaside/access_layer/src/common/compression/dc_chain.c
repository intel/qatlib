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
 * @file dc_chain.c
 *
 * @ingroup Dc_Chaining
 *
 * @description
 *      Implementation of the chaining session operations.
 *
 *****************************************************************************/

/*
 *******************************************************************************
 * Include public/global header files
 *******************************************************************************
 */
#ifndef ICP_DC_ONLY
#include "cpa.h"

#include "icp_qat_fw.h"
#include "icp_qat_fw_comp.h"
#include "icp_qat_hw.h"

/*
 *******************************************************************************
 * Include private header files
 *******************************************************************************
 */
#include "dc_chain.h"
#include "dc_capabilities.h"
#include "dc_datapath.h"
#include "dc_stats.h"
#include "lac_mem_pools.h"
#include "lac_buffer_desc.h"
#include "sal_service_state.h"
#include "sal_qat_cmn_msg.h"
#include "lac_sym_qat_hash_defs_lookup.h"
#include "sal_string_parse.h"
#include "lac_sym.h"
#include "lac_session.h"
#include "lac_sym_qat.h"
#include "lac_sym_hash.h"
#include "lac_sym_alg_chain.h"
#include "lac_sym_auth_enc.h"
#include "dc_session.h"
#include "dc_crc64.h"

#define DC_CHAIN_COMPUTE_KEY(huffType, dcDir, sessType)                        \
    ((huffType << 8) | (dcDir << 4) | sessType)
#define CY_CHAIN_COMPUTE_KEY(cyOpType, cyDir, sessType)                        \
    ((cyOpType << 8) | (cyDir << 4) | sessType)

static const dc_chain_cmd_tbl_t dc_chain_cmd_table[] = {
    /* link0: additional=2(hash)|dir=0(rsvd)|type=1(crypto)
     * link1: additional=0(static)|dir=0(compression)|type=0(comp)
     */
    { 0x201,
      0x0,
      0x0,
      ICP_QAT_FW_CHAINING_CMD_HASH_STATIC_COMP,
      ICP_QAT_FW_CHAINING_20_CMD_HASH_COMPRESS },
    /* link0: additional=2(hash)|dir=0(rsvd)|type=1(crypto)
     * link1: additional=2(dynamic )|dir=0(compression)|type=0(comp)
     */
    { 0x201,
      0x200,
      0x0,
      ICP_QAT_FW_CHAINING_CMD_HASH_DYNAMIC_COMP,
      ICP_QAT_FW_CHAINING_20_CMD_HASH_COMPRESS },
    /* link0: additional=2(dynamic)|dir=0(compression)|type=0(comp)
     * link1: additional=3(algChain)|dir=1(encrypt)|type=1(crypto)
     */
    { 0x200,
      0x311,
      0x0,
      ICP_QAT_FW_NO_CHAINING,
      ICP_QAT_FW_CHAINING_20_CMD_COMPRESS_ENCRYPT },
    /* link0: additional=3(algChain)|dir=2(decrypt)|type=1(crypto)
     * link1: additional=0(rsvd)|dir=1(decomp)|type=0(comp)
     */
    { 0x321,
      0x10,
      0x0,
      ICP_QAT_FW_NO_CHAINING,
      ICP_QAT_FW_CHAINING_20_CMD_DECRYPT_DECOMPRESS },
};

#ifdef ICP_PARAM_CHECK
#define NUM_OF_SESSION_SUPPORT 2

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Check that chaining HASH setup data is valid
 *
 * @description
 *      Check that chaining HASH setup data in the CpaCySymHashSetupData is
 *      valid
 *
 * @param[in]    pHashSetupData      Pointer to an CpaCySymHashSetupData
 *                                   structures.
 * @param[in]    hw_gen              Hardware generation
 * @param[in]    operation           Chaining operation type
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_CheckHashSetupData(const CpaCySymHashSetupData *pHashSetupData,
                                  dc_hw_gen_types_t hw_gen,
                                  CpaDcChainOperations operation)
{
    LAC_CHECK_NULL_PARAM(pHashSetupData);

    {
        /* Support SHA1, SHA224 and SHA256 */
        LAC_CHECK_STATEMENT_LOG(
            pHashSetupData->hashAlgorithm != CPA_CY_SYM_HASH_SHA1 &&
                pHashSetupData->hashAlgorithm != CPA_CY_SYM_HASH_SHA224 &&
                pHashSetupData->hashAlgorithm != CPA_CY_SYM_HASH_SHA256,
            "%s",
            "Only algorithms SHA1, SHA224, SHA256 are "
            "supported");
        LAC_CHECK_STATEMENT_LOG(
            (CPA_CY_SYM_HASH_MODE_PLAIN != pHashSetupData->hashMode),
            "Invalid CY hashMode=0x%x",
            pHashSetupData->hashMode);
    }
    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Check that chaining session data is valid
 *
 * @description
 *      Check that all the parameters defined in the pSessionData are valid
 *
 * @param[in]       operation        Chaining operation type
 * @param[in]       numSessions      Number of chaining sessions
 * @param[in]       pSessionData     Pointer to an array of
 *                                   CpaDcChainSessionSetupData
 *                                   structures.There should be numSessions
 *                                   entries in the array.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_UNSUPPORTED    Unsupported operation passed in
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_CheckSessionData(CpaInstanceHandle dcInstance,
                                CpaDcChainOperations operation,
                                Cpa8U numSessions,
                                const CpaDcChainSessionSetupData *pSessionData)
{
    dc_capabilities_t *pDcCapabilities = NULL;
    sal_compression_service_t *pService =
        (sal_compression_service_t *)dcInstance;
    CpaCySymSessionSetupData *pCySetupData = NULL;
    CpaDcSessionSetupData *pDcSetupData = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean capSupport = CPA_FALSE;

    pDcCapabilities = &pService->dc_capabilities;

    /* Currently all supported chaining operations have
     * exactly 2 sessions. This is defined by NUM_OF_SESSION_SUPPORT */

    LAC_CHECK_STATEMENT_LOG(numSessions != NUM_OF_SESSION_SUPPORT,
                            "%s",
                            "Wrong number of sessions "
                            "for a chaining operation");

    switch (operation)
    {
        case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
            pCySetupData = pSessionData[0].pCySetupData;
            pDcSetupData = pSessionData[1].pDcSetupData;

            LAC_CHECK_NULL_PARAM(pCySetupData);
            LAC_CHECK_NULL_PARAM(pDcSetupData);

            /* Check for valid/supported DC chaining parameters */
            LAC_CHECK_STATEMENT_LOG(
                (pSessionData[0].sessType != CPA_DC_CHAIN_SYMMETRIC_CRYPTO),
                "Invalid chaining cySessType=0x%x for HASH_THEN_COMPRESS",
                pSessionData[0].sessType);

            LAC_CHECK_STATEMENT_LOG(
                (pSessionData[1].sessType != CPA_DC_CHAIN_COMPRESS_DECOMPRESS),
                "Invalid chaining dcSessType=0x%x for HASH_THEN_COMPRESS",
                pSessionData[1].sessType);

            status = dcGetHashChainingCapabilityStatus(
                pDcCapabilities, pDcSetupData->compType, &capSupport);
            LAC_CHECK_STATUS(status);
            if (capSupport != CPA_TRUE)
            {
                LAC_INVALID_PARAM_LOG1("Unsupported DC compType=0x%x for "
                                       "HASH_THEN_COMPRESS chaining",
                                       pDcSetupData->compType);
                return CPA_STATUS_UNSUPPORTED;
            }

            /* Check for valid/supported Symmetric Crypto parameters */
            LAC_CHECK_STATEMENT_LOG(
                (pCySetupData->symOperation != CPA_CY_SYM_OP_HASH),
                "Invalid CY symOperation=0x%x for HASH_THEN_COMPRESS chaining",
                pCySetupData->symOperation);

            LAC_CHECK_STATEMENT_LOG(
                (pCySetupData->digestIsAppended == CPA_TRUE),
                "Invalid CY digestIsAppended=0x%x for HASH_THEN_COMPRESS "
                "chaining",
                pCySetupData->digestIsAppended);

            /* Check for valid/supported DC parameters */
            LAC_CHECK_STATEMENT_LOG(
                (pDcSetupData->sessDirection != CPA_DC_DIR_COMPRESS),
                "Invalid DC sessDirection=0x%x for HASH_THEN_COMPRESS chaining",
                pDcSetupData->sessDirection);

            LAC_CHECK_STATEMENT_LOG(
                (pDcSetupData->huffType == CPA_DC_HT_PRECOMP),
                "Invalid DC huffType=0x%x for HASH_THEN_COMPRESS chaining",
                pDcSetupData->huffType);

            if (pDcSetupData->sessState != CPA_DC_STATELESS)
            {
                LAC_INVALID_PARAM_LOG2(
                    "Invalid DC sessState=0x%x for %d chaining operation",
                    pDcSetupData->sessState,
                    operation);
                return CPA_STATUS_INVALID_PARAM;
            }

            /* Check for supported hash parameters */
            status = dcChainSession_CheckHashSetupData(
                &pCySetupData->hashSetupData,
                pDcCapabilities->deviceData.hw_gen,
                operation);
            LAC_CHECK_STATUS(status);
            break;
        case CPA_DC_CHAIN_COMPRESS_THEN_AEAD:
        case CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS:
        case CPA_DC_CHAIN_COMPRESS_THEN_HASH:
        case CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT:
        case CPA_DC_CHAIN_COMPRESS_THEN_HASH_ENCRYPT:
        case CPA_DC_CHAIN_COMPRESS_THEN_ENCRYPT_HASH:
        case CPA_DC_CHAIN_HASH_VERIFY_THEN_DECOMPRESS:
        case CPA_DC_CHAIN_DECRYPT_THEN_DECOMPRESS:
        case CPA_DC_CHAIN_HASH_VERIFY_DECRYPT_THEN_DECOMPRESS:
        case CPA_DC_CHAIN_DECRYPT_HASH_VERIFY_THEN_DECOMPRESS:
        case CPA_DC_CHAIN_DECOMPRESS_THEN_HASH_VERIFY:
        case CPA_DC_CHAIN_COMPRESS_THEN_AEAD_THEN_HASH:
            LAC_LOG_ERROR1("Chaining operation 0x%x not supported", operation);
            return CPA_STATUS_UNSUPPORTED;
        default:
            LAC_INVALID_PARAM_LOG1("Invalid operation 0x%x\n", operation);
            return CPA_STATUS_INVALID_PARAM;
    }

    return status;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialization for chaining sessions
 *
 * @description
 *      Check for supported Sym Crypto operations as part of DC Chain
 *
 * @param[in]    pCySessDesc         Session descriptor for Sym Crypto
 *                                   operation.
 * @param[in]    operation           Chaining operation type
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid Sym Crypto parameter
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_CheckCySessDesc(const lac_session_desc_t *pCySessDesc,
                               CpaDcChainOperations operation)
{
    LAC_CHECK_NULL_PARAM(pCySessDesc);

    /* Restrict DC Chain Sym Crypto operations to supported/validated
     * combinations when used as part of a chain operation */

    switch (operation)
    {
        case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
            LAC_CHECK_STATEMENT_LOG(
                (CPA_CY_SYM_OP_HASH != pCySessDesc->symOperation),
                "Invalid CY symOperation=0x%x for HASH_THEN_COMPRESS chaining",
                pCySessDesc->symOperation);

            LAC_CHECK_STATEMENT_LOG(
                ((CPA_CY_SYM_HASH_MODE_PLAIN != pCySessDesc->hashMode) &&
                 (CPA_CY_SYM_HASH_MODE_AUTH != pCySessDesc->hashMode)),
                "Invalid CY hashMode=0x%x for HASH_THEN_COMPRESS chaining",
                pCySessDesc->hashMode);

            LAC_CHECK_STATEMENT_LOG((CPA_FALSE != pCySessDesc->isAuthEncryptOp),
                                    "Invalid CY isAuthEncryptOp=0x%x for "
                                    "HASH_THEN_COMPRESS chaining",
                                    pCySessDesc->isAuthEncryptOp);

            LAC_CHECK_STATEMENT_LOG(
                (CPA_FALSE != pCySessDesc->isCipher),
                "Invalid CY isCipher=0x%x for HASH_THEN_COMPRESS chaining",
                pCySessDesc->isCipher);

            LAC_CHECK_STATEMENT_LOG(
                (CPA_TRUE != pCySessDesc->isAuth),
                "Invalid CY isAuth=0x%x for HASH_THEN_COMPRESS chaining",
                pCySessDesc->isAuth);

            break;
        default:
            LAC_INVALID_PARAM_LOG1("Unsupported DC chaining operation=0x%x",
                                   operation);
            return CPA_STATUS_INVALID_PARAM;
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialization for chaining sessions
 *
 * @description
 *      Check for supported compression operations as part of DC Chain
 *
 * @param[in]    pDcSessDesc         Session descriptor for compression
 *                                   operation.
 * @param[in]    operation           Chaining operation type
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid compression parameter
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_CheckDcSessDesc(const dc_session_desc_t *pDcSessDesc,
                               CpaDcChainOperations operation,
                               dc_capabilities_t *pDcCapabilities)
{
    CpaBoolean staticSupported = CPA_FALSE;

    LAC_CHECK_NULL_PARAM(pDcSessDesc);

    if ((CPA_DC_DEFLATE == pDcSessDesc->compType) &&
        (CPA_DC_HT_STATIC == pDcSessDesc->huffType))
    {
        staticSupported = DC_CAPS_DEFLATE_TYPE_SUPPORT_GET(
            pDcCapabilities->deflate.typeSupport,
            DC_CAPS_DEFLATE_TYPE_STATIC,
            DC_CAPS_DEFLATE_TYPE_SUPPORTED);

        if (CPA_FALSE == staticSupported)
        {
            LAC_UNSUPPORTED_PARAM_LOG(
                "Static huffman encoding is not supported "
                "on current instance");
            return CPA_STATUS_UNSUPPORTED;
        }
    }

    return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialization for chaining sessions
 *
 * @description
 *      Check for supported compression operations as part of DC Chain
 *
 * @param[in]    pChainSessDesc      Session descriptor for DC Chain
 *                                   requests.
 * @param[in]    dcInstance          Instance handle
 * @param[in]    operation           Chaining operation type
 * @param[in]    numSessions         Number of sessions in the chain operation
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM  Invalid compression parameter
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_CheckChainSessDesc(const dc_chain_session_head_t *pChainSessDesc,
                                  const CpaInstanceHandle dcInstance,
                                  const CpaDcChainOperations operation,
                                  const Cpa8U numSessions)
{
    sal_compression_service_t *pDcService =
        (sal_compression_service_t *)dcInstance;
    Cpa8U *pTemp;

    LAC_CHECK_NULL_PARAM(pChainSessDesc);

    LAC_CHECK_STATEMENT_LOG(numSessions != NUM_OF_SESSION_SUPPORT,
                            "%s",
                            "Wrong number of sessions "
                            "for a chaining operation");

    pTemp = (Cpa8U *)pChainSessDesc + sizeof(dc_chain_session_head_t);

    /* Restrict DC chaining operations to supported combinations */
    switch (operation)
    {
        case CPA_DC_CHAIN_HASH_THEN_COMPRESS:
            if (!(pDcService->generic_service_info.dcExtendedFeatures &
                  DC_CHAIN_HASH_THEN_COMPRESS_EXTENDED_CAPABILITY))
            {
                LAC_INVALID_PARAM_LOG(
                    "HW does not support chaining operation hash and compress");
                return CPA_STATUS_UNSUPPORTED;
            }

            LAC_CHECK_STATEMENT_LOG(
                (DC_CHAIN_TYPE_GET(pTemp) != CPA_DC_CHAIN_SYMMETRIC_CRYPTO),
                "Invalid chaining cySessType=0x%x for HASH_THEN_COMPRESS",
                DC_CHAIN_TYPE_GET(pTemp));

            /* Move to the next session data */
            pTemp += (LAC_SYM_SESSION_SIZE + sizeof(CpaDcChainSessionType));

            LAC_CHECK_STATEMENT_LOG(
                (DC_CHAIN_TYPE_GET(pTemp) != CPA_DC_CHAIN_COMPRESS_DECOMPRESS),
                "Invalid chaining dcSessType=0x%x for HASH_THEN_COMPRESS",
                DC_CHAIN_TYPE_GET(pTemp));
            break;
        default:
            LAC_INVALID_PARAM_LOG1("Invalid chaining operation %x", operation);
            return CPA_STATUS_INVALID_PARAM;
    }
    return CPA_STATUS_SUCCESS;
}
#endif

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Get the size for chaining sessions
 *
 * @description
 *      Get the size for chaining sessions, it counts how many bytes are needed
 *      for one chaining request, and it is called by cpaDcChainGetSessionSize
 *
 * @param[in]       dcInstance       Instance handle
 * @param[in]       pSessionData     Pointer to an array of
 *                                   CpaDcChainSessionSetupData
 *                                   structures. There should be numSessions
 *                                   entries in the array.
 * @param[in]       numSessions      Number of chaining sessions
 * @param[out]      pSessionSize     On return, this parameter will be the size
 *                                   of the memory that will be required by
 *                                   cpaDcChainInitSession() for session data.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 *
 *****************************************************************************/
STATIC CpaStatus dcChainGetSessionSize(CpaInstanceHandle dcInstance,
                                       CpaDcChainSessionSetupData *pSessionData,
                                       Cpa8U numSessions,
                                       Cpa32U *pSessionSize)
{
    Cpa32U sessSize;
    Cpa32U i;

    sessSize = sizeof(dc_chain_session_head_t);

    for (i = 0; i < numSessions; i++)
    {
        sessSize += sizeof(CpaDcChainSessionType) + LAC_64BYTE_ALIGNMENT +
                    sizeof(LAC_ARCH_UINT);
        if (pSessionData[i].sessType == CPA_DC_CHAIN_COMPRESS_DECOMPRESS)
            sessSize += sizeof(dc_session_desc_t);
        else
            sessSize += sizeof(lac_session_desc_t);
    }

    *pSessionSize = sessSize;

    return CPA_STATUS_SUCCESS;
}

CpaStatus cpaDcChainGetSessionSize(CpaInstanceHandle dcInstance,
                                   CpaDcChainOperations operation,
                                   Cpa8U numSessions,
                                   CpaDcChainSessionSetupData *pSessionData,
                                   Cpa32U *pSessionSize)

{
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pSessionSize);
    LAC_CHECK_STATEMENT_LOG(numSessions != NUM_OF_SESSION_SUPPORT,
                            "%s",
                            "Invalid number of sessions");
#endif

    return dcChainGetSessionSize(
        dcInstance, pSessionData, numSessions, pSessionSize);
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Generate command ID
 *
 * @description
 *      Generate command ID from session data and number of sessions
 *
 * @param[in]       pSessionData     Pointer to an array of
 *                                   CpaDcChainSessionSetupData
 *                                   structures.
 * @param[in]       numSessions      Number of chaining sessions
 * @param[in]       cmd              Command ID
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus
dcChainSession_GenerateCmd(CpaInstanceHandle dcInstance,
                           CpaDcChainSessionSetupData *pSessionData,
                           Cpa8U numSessions,
                           icp_qat_comp_chain_cmd_id_t *cmd)
{
    Cpa16U key[DC_CHAIN_MAX_LINK] = {0};
    CpaDcChainSessionType sessType;
    CpaCySymCipherSetupData const *pCipherSetupData = NULL;
    CpaDcSessionDir dcDir = CPA_DC_DIR_COMPRESS;
    CpaCySymCipherDirection cyDir = CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    CpaDcHuffType huffType;
    CpaCySymOp cyOpType = CPA_CY_SYM_OP_NONE;
    Cpa32U i, numOfCmds;

    for (i = 0; i < numSessions; i++)
    {
        sessType = pSessionData[i].sessType;
        if (CPA_DC_CHAIN_COMPRESS_DECOMPRESS == sessType)
        {
            dcDir = pSessionData[i].pDcSetupData->sessDirection;
            if (dcDir == CPA_DC_DIR_COMPRESS)
                huffType = pSessionData[i].pDcSetupData->huffType;
            else
                huffType = CPA_DC_HT_STATIC;
            key[i] = DC_CHAIN_COMPUTE_KEY(huffType, dcDir, sessType);
        }
        else
        {
            cyOpType = pSessionData[i].pCySetupData->symOperation;
            pCipherSetupData = &(pSessionData[i].pCySetupData->cipherSetupData);
            cyDir = pCipherSetupData->cipherDirection;
            if (CPA_CY_SYM_OP_HASH == cyOpType)
            {
                cyDir = NOT_APPLICABLE;
            }
            key[i] = CY_CHAIN_COMPUTE_KEY(cyOpType, cyDir, sessType);
        }
    }

    numOfCmds = sizeof(dc_chain_cmd_table) / sizeof(dc_chain_cmd_tbl_t);
    for (i = 0; i < numOfCmds; i++)
    {
        if ((key[0] == dc_chain_cmd_table[i].link0_key) &&
            (key[1] == dc_chain_cmd_table[i].link1_key) &&
            (key[2] == dc_chain_cmd_table[i].link2_key))
        {
                *cmd = (icp_qat_comp_chain_cmd_id_t)dc_chain_cmd_table[i]
                           .cmd_20_id;

            /* Check if chaining is supported for the found operation */
            if (ICP_QAT_FW_NO_CHAINING == *cmd)
            {
                return CPA_STATUS_FAIL;
            }
            else
            {
                return CPA_STATUS_SUCCESS;
            }
        }
    }
    return CPA_STATUS_FAIL;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Initialization for chaining sessions
 *
 * @description
 *      Initialization for chaining sessions, it is called by
 *      cpaDcChainInitSession
 *
 * @param[in]       dcInstance      Instance handle derived from discovery
 *                                  functions.
 * @param[in,out]   pSessionHandle  Pointer to a session handle.
 * @param[in,out]   pSessionData    Pointer to an array of
 *                                  CpaDcChainSessionSetupData structures.
 *                                  There should be numSessions entries in the
 *                                  array.
 * @param[in]       numSessions     Number of sessions for the chaining
 * @param[in]       callbackFn      For synchronous operation this callback
 *                                  shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 *
 *****************************************************************************/
STATIC CpaStatus dcChainInitSessions(CpaInstanceHandle dcInstance,
                                     CpaDcSessionHandle pSessionHandle,
                                     CpaDcChainSessionSetupData *pSessionData,
                                     Cpa8U numSessions,
                                     CpaDcCallbackFn callbackFn)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    dc_chain_session_head_t *pSessHead;
    icp_qat_comp_chain_cmd_id_t chainCmd;
    Cpa8U *pTemp;
    Cpa32U i;
    CpaBoolean cyInitialized = CPA_FALSE;
    CpaBoolean dcInitialized = CPA_FALSE;
    lac_session_desc_t *pCySessDesc = NULL;

    pSessHead = (dc_chain_session_head_t *)pSessionHandle;
    pTemp = (Cpa8U *)pSessionHandle + sizeof(dc_chain_session_head_t);
    for (i = 0; i < numSessions; i++)
    {
        if (pSessionData[i].sessType == CPA_DC_CHAIN_COMPRESS_DECOMPRESS)
        {
            *(CpaDcChainSessionType *)pTemp = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            pTemp += sizeof(CpaDcChainSessionType);

            status = dcInitSession(
                dcInstance,
                (CpaDcSessionHandle)pTemp,
                (CpaDcSessionSetupData *)pSessionData[i].pDcSetupData,
                NULL,
                NULL);

            if (CPA_STATUS_SUCCESS != status)
            {
                if (CPA_TRUE == cyInitialized)
                {
                    /* For crypto, destroy spinlock and mutex */
                    pCySessDesc = pSessHead->pCySessionDesc;
#ifdef ICP_PARAM_CHECK
                    LAC_CHECK_NULL_PARAM(pCySessDesc);
#endif
                    LAC_SPINLOCK_DESTROY(&pCySessDesc->requestQueueLock);
                    osalAtomicSet(0, &pCySessDesc->accessLock);
                }
                LAC_LOG_ERROR("Init compression session failure\n");
                return status;
            }
            pSessHead->pDcSessionDesc = DC_SESSION_DESC_FROM_CTX_GET(pTemp);
            LAC_CHECK_NULL_PARAM(pSessHead->pDcSessionDesc);
            pTemp += DC_COMP_SESSION_SIZE;
            dcInitialized = CPA_TRUE;
        }
        else
        {
            *(CpaDcChainSessionType *)pTemp = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            pTemp += sizeof(CpaDcChainSessionType);

            status = LacSym_InitSession(
                dcInstance,
                NULL,
                (CpaCySymSessionSetupData *)pSessionData[i].pCySetupData,
                CPA_FALSE,
                (CpaCySymSessionCtx)pTemp);
            if (CPA_STATUS_SUCCESS != status)
            {
                if (CPA_TRUE == dcInitialized)
                {
                    /* For DC, destroy spinlock */
                    LAC_SPINLOCK_DESTROY(
                        &(pSessHead->pDcSessionDesc->updateLock));
                }
                LAC_LOG_ERROR("Init symmetric session failure\n");
                return status;
            }
            pSessHead->pCySessionDesc =
                LAC_SYM_SESSION_DESC_FROM_CTX_GET(pTemp);
            pTemp += LAC_SYM_SESSION_SIZE;
            cyInitialized = CPA_TRUE;
        }
    }
    pSessHead->pdcChainCb = ((void *)NULL != (void *)callbackFn)
                                ? callbackFn
                                : LacSync_GenWakeupSyncCaller;

    osalAtomicSet(0, &pSessHead->pendingChainCbCount);
    /*Fill the pre-build header*/
    status = dcChainSession_GenerateCmd(
        dcInstance, pSessionData, numSessions, &chainCmd);
    if (CPA_STATUS_SUCCESS != status)
    {
        status = cpaDcChainRemoveSession(dcInstance, pSessionHandle);
        if (CPA_STATUS_SUCCESS != status)
        {
            LAC_LOG_ERROR1("cpaDcChainRemoveSession returned %d status",
                           status);
        }
        LAC_LOG_ERROR("generate chained command failure\n");
        return CPA_STATUS_FAIL;
    }

    /* Store number of links in the chain */
    pSessHead->numLinks = numSessions;
        /* Fill chaining request descriptor header */
        pSessHead->hdr.comn_hdr2.service_cmd_id = chainCmd;
        pSessHead->hdr.comn_hdr2.service_type =
            ICP_QAT_FW_COMN_REQ_CPM_FW_COMP_CHAIN;
        pSessHead->hdr.comn_hdr2.hdr_flags =
            ICP_QAT_FW_COMN_HDR_FLAGS_BUILD(ICP_QAT_FW_COMN_REQ_FLAG_SET);
        pSessHead->hdr.comn_hdr2.resrvd1 = 0;
        pSessHead->hdr.comn_hdr2.serv_specif_flags =
            ICP_QAT_FW_COMP_CHAIN_REQ_FLAGS_BUILD(
                ICP_QAT_FW_COMP_CHAIN_NO_APPEND_CRC,
                ICP_QAT_FW_COMP_CHAIN_NO_VERIFY,
                ICP_QAT_FW_COMP_CHAIN_NO_DERIVE_KEY,
                ICP_QAT_FW_COMP_CHAIN_NO_CRC64_CTX);
        pSessHead->hdr.comn_hdr2.comn_req_flags = ICP_QAT_FW_COMN_FLAGS_BUILD(
            DC_DEFAULT_QAT_PTR_TYPE, QAT_COMN_CD_FLD_TYPE_16BYTE_DATA);
        pSessHead->hdr.comn_hdr2.extended_serv_specif_flags = 0;

    return status;
}

CpaStatus cpaDcChainInitSession(CpaInstanceHandle dcInstance,
                                CpaDcSessionHandle pSessionHandle,
                                CpaDcChainOperations operation,
                                Cpa8U numSessions,
                                CpaDcChainSessionSetupData *pSessionData,
                                CpaDcCallbackFn callbackFn)

{
    CpaInstanceHandle insHandle = NULL;
    sal_compression_service_t *pService = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

    pService = (sal_compression_service_t *)insHandle;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_INSTANCE_HANDLE(insHandle);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    LAC_CHECK_NULL_PARAM(pSessionData);
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    SAL_RUNNING_CHECK(pService);
    if (dcChainSession_CheckSessionData(
            insHandle, operation, numSessions, pSessionData) !=
        CPA_STATUS_SUCCESS)
    {
        return CPA_STATUS_INVALID_PARAM;
    }
    if (NULL == pService->pDcChainService)
    {
        return CPA_STATUS_UNSUPPORTED;
    }
#endif

    return dcChainInitSessions(
        insHandle, pSessionHandle, pSessionData, numSessions, callbackFn);
}

CpaStatus cpaDcChainRemoveSession(const CpaInstanceHandle dcInstance,
                                  CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;
    dc_chain_session_head_t *pSessHead = NULL;
    Cpa64U numPendingRequest = 0;
    sal_compression_service_t *pService = NULL;
    lac_session_desc_t *pCySessDesc = NULL;
    dc_session_desc_t *pSessionDesc = NULL;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif
    pSessHead = (dc_chain_session_head_t *)pSessionHandle;

    pSessionDesc = pSessHead->pDcSessionDesc;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif
    pService = (sal_compression_service_t *)insHandle;
    if (NULL == pService->pDcChainService)
    {
        return CPA_STATUS_UNSUPPORTED;
    }

    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    numPendingRequest = osalAtomicGet(&(pSessHead->pendingChainCbCount));

    /* Check if there are  pending requests */
    if (0 != numPendingRequest)
    {
        LAC_LOG_ERROR1("There are %llu chaining requests pending",
                       numPendingRequest);
        status = CPA_STATUS_RETRY;
    }

    /* For crypto, destroy spinlock and mutex */
    pCySessDesc = pSessHead->pCySessionDesc;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pCySessDesc);
#endif
    LAC_SPINLOCK_DESTROY(&pCySessDesc->requestQueueLock);
    osalAtomicSet(0, &pCySessDesc->accessLock);

    if (CPA_DC_STATELESS == pSessHead->pDcSessionDesc->sessState)
    {
        LAC_SPINLOCK_DESTROY(&(pSessHead->pDcSessionDesc->updateLock));
    }

    /* Free the CRC lookup table if one was allocated */
    if (NULL != pSessionDesc->crcConfig.pCrcLookupTable)
    {
        LAC_OS_FREE(pSessionDesc->crcConfig.pCrcLookupTable);
    }
    return status;
}

CpaStatus cpaDcChainResetSession(const CpaInstanceHandle dcInstance,
                                 CpaDcSessionHandle pSessionHandle)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle insHandle = NULL;
    dc_session_desc_t *pDcDescriptor = NULL;
    dc_chain_session_head_t *pSessHead = NULL;
    Cpa64U numPendingRequest = 0;
    Cpa8U *pTemp;
    Cpa32U i;
    sal_compression_service_t *pService = NULL;
#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
#endif
    pSessHead = (dc_chain_session_head_t *)pSessionHandle;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
#endif
    pService = (sal_compression_service_t *)insHandle;
    if (NULL == pService->pDcChainService)
    {
        return CPA_STATUS_UNSUPPORTED;
    }
    /* Check if SAL is running otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    numPendingRequest = osalAtomicGet(&(pSessHead->pendingChainCbCount));

    /* Check if there are stateless pending requests */
    if (0 != numPendingRequest)
    {
        LAC_LOG_ERROR1("There are %llu chaining requests pending",
                       numPendingRequest);
        return CPA_STATUS_RETRY;
    }

    pTemp = (Cpa8U *)pSessionHandle + sizeof(dc_chain_session_head_t);
    for (i = 0; i < pSessHead->numLinks; i++)
    {
        if (DC_CHAIN_TYPE_GET(pTemp) == CPA_DC_CHAIN_SYMMETRIC_CRYPTO)
        {
            pTemp += sizeof(CpaDcChainSessionType);
            pTemp += LAC_SYM_SESSION_SIZE;
        }
        else
        {
            pTemp += sizeof(CpaDcChainSessionType);
            pDcDescriptor = DC_SESSION_DESC_FROM_CTX_GET(pTemp);
            break;
        }
    }
    LAC_CHECK_NULL_PARAM(pDcDescriptor);
    /* Reset chaining session descriptor */
    pDcDescriptor->requestType = DC_REQUEST_FIRST;
    pDcDescriptor->cumulativeConsumedBytes = 0;

    return status;
}

/**
 * ************************************************************************
 * @ingroup Dc_Chaining
 *     Create compression request and link it to chaining request
 *
 * @param[in]    dcInstance          Compression instance handle
 * @param[out]   pChainCookie        Chaining cookie
 * @param[in]    operation           Chaining operation type
 * @param[in]    pSessionHandle      Compression session handle
 * @param[in]    pDcOpDataExt        Pointer to compression operation data
 * @param[in]    pDcCookie           Compression cookie
 * @param[in]    pSrcBuff            Source buffer for compression
 * @param[in]    pDestBuff           Destination buffer for comprssion
 * @param[in]    pResults            Chaining result
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_UNSUPPORTED    Action not support
 *
 * *************************************************************************/
STATIC CpaStatus dcChainPrepare_CompRequest(CpaInstanceHandle dcInstance,
                                            dc_chain_cookie_t *pChainCookie,
                                            CpaDcChainOperations operation,
                                            Cpa8U *pSessionHandle,
                                            dc_opdata_ext_t *pDcOpDataExt,
                                            dc_compression_cookie_t *pDcCookie,
                                            CpaBufferList *pSrcBuff,
                                            CpaBufferList *pDestBuff,
                                            CpaDcChainRqResults *pResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    dc_session_desc_t *pDcSessDesc = NULL;
    sal_compression_service_t *pDcService =
        (sal_compression_service_t *)dcInstance;
    sal_dc_chain_service_t *pChainService = pDcService->pDcChainService;
    CpaDcOpData *pDcOpData = NULL;
    dc_request_dir_t compDecomp;
    CpaDcRqResults dcResults = {0};
    Cpa64U rspDescPhyAddr = 0;
    dc_cnv_mode_t cnvMode;
    void *pDcLinkRsp = NULL;
    icp_qat_fw_chain_stor2_req_t *pChainStor2Req = NULL;
    icp_qat_fw_comp_req_t *pMsg = NULL;
    dc_capabilities_t *pDcCapabilities = NULL;
    CpaBoolean statefulLiteUnsupported = CPA_FALSE;

    pDcSessDesc = DC_SESSION_DESC_FROM_CTX_GET(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pDcSessDesc);

    pDcCapabilities = &pDcService->dc_capabilities;
    statefulLiteUnsupported = pDcCapabilities->statefulLiteUnsupported;

    /* Legacy CpaDcOpData. DC OpData extensions are not supported. */
    if (DC_OPDATA_TYPE0 == pDcOpDataExt->opDataType)
    {
        pDcOpData = (CpaDcOpData *)pDcOpDataExt->pOpData;
    }
    else
    {
        pDcOpData = &((CpaDcOpData2 *)pDcOpDataExt->pOpData)->dcOpData;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pDcOpData);
    LAC_CHECK_STATEMENT_LOG(
        pDcOpData->flushFlag == CPA_DC_FLUSH_SYNC,
        "%s",
        "CPA_DC_FLUSH_SYNC not supported for compression.\n");
    LAC_CHECK_STATEMENT_LOG(
        pDcOpData->flushFlag == CPA_DC_FLUSH_NONE,
        "%s",
        "CPA_DC_FLUSH_NONE flag not supported for compression.\n");

    if (CPA_STATUS_SUCCESS !=
        dcChainSession_CheckDcSessDesc(pDcSessDesc, operation, pDcCapabilities))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif

    if (pDcOpData->compressAndVerifyAndRecover && pDcCapabilities->cnv.recovery)
        cnvMode = DC_CNVNR;
    else if (pDcOpData->compressAndVerify && pDcCapabilities->cnv.supported)
        cnvMode = DC_CNV;
    else
        cnvMode = DC_NO_CNV;

    if (CPA_DC_DIR_COMPRESS == pDcSessDesc->sessDirection)
        compDecomp = DC_COMPRESSION_REQUEST;
    else
        compDecomp = DC_DECOMPRESSION_REQUEST;

    if (CPA_FALSE == pDcOpData->compressAndVerify)
    {
        LAC_UNSUPPORTED_PARAM_LOG(
            "Data compression without verification not allowed");
        return CPA_STATUS_UNSUPPORTED;
    }

    /* Add DC Chaining info to the compression cookie */
    pDcCookie->dcChain.isDcChaining = CPA_TRUE;

    /* This is the common DC function to create the requests for
     * compression or decompression. It creates the DC request
     * message but does not send it. */
    status = dcCreateRequest(pDcCookie,
                             pDcService,
                             pDcSessDesc,
                             pSessionHandle,
                             pSrcBuff,
                             pDestBuff,
                             &dcResults,
                             pDcOpData->flushFlag,
                             pDcOpData,
                             NULL,
                             compDecomp,
                             cnvMode,
                             NULL);
    pDcCookie->pResults = NULL;

    /* If this is not a DC_REQUEST_FIRST then for DC Chaining we must
     * re-seed both adler32 and crc32 with the previous checksums */
    pMsg = (icp_qat_fw_comp_req_t *)&pDcCookie->request;
    if ((DC_REQUEST_FIRST != pDcSessDesc->requestType) &&
        (CPA_DC_STATELESS == pDcSessDesc->sessState) &&
        (CPA_TRUE != statefulLiteUnsupported))
    {
        pMsg->comp_pars.crc.legacy.initial_adler = pResults->adler32;
        pMsg->comp_pars.crc.legacy.initial_crc32 = pResults->crc32;
    }

    LAC_CHECK_STATUS(status);

    pDcLinkRsp = Lac_MemPoolEntryAlloc(pChainService->dc_chain_serv_resp_pool);
    if (NULL == pDcLinkRsp)
    {
        return CPA_STATUS_RESOURCE;
    }
    else if ((void *)CPA_STATUS_RETRY == pDcLinkRsp)
    {
        return CPA_STATUS_RETRY;
    }

    rspDescPhyAddr = (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pDcService->generic_service_info, pDcLinkRsp);
    pChainCookie->pDcRspAddr = pDcLinkRsp;
    pChainCookie->pDcCookieAddr = pDcCookie;

        pChainStor2Req = (icp_qat_fw_chain_stor2_req_t *)&pChainCookie->request;
        pChainStor2Req->compReqAddr =
            (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                pDcService->generic_service_info, &pDcCookie->request);
        pChainStor2Req->compRespAddr = rspDescPhyAddr;

    return status;
}

/**
 * ************************************************************************
 * @ingroup Dc_Chaining
 *     Create symmetric crypto request for chaining request
 *     and link crypto request address to chaining request,
 *     FW will parse chaining request on ring to get crypto
 *     request address.
 *
 * @param[in]    dcInstance          Chaining Instance handle
 * @param[in,out]    pChainCookie    Chaining cookie
 * @param[in]    operation           Chaining operation type
 * @param[in]    pSessionHandle      Chaining session handle
 * @param[in]    pCyCookie           Symmetric crypto cookie
 * @param[in]    pCySymOpExt         Symmetric crypto operation data
 * @param[in]    pSrcBuffer          Source buffer for crypto
 * @param[in]    pDestBuffer         Destination buffer for crypto
 * @param[in,out]    pResults        Chaining response result
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Error related to system resources
 * @retval CPA_STATUS_RETRY          Need to try it again
 *
 * *************************************************************************/
STATIC CpaStatus dcChainPrepare_SymRequest(CpaInstanceHandle dcInstance,
                                           dc_chain_cookie_t *pChainCookie,
                                           CpaDcChainOperations operation,
                                           Cpa8U *pSessionHandle,
                                           lac_sym_bulk_cookie_t *pCyCookie,
                                           cy_opdata_ext_t *pCySymOpExt,
                                           CpaBufferList *pSrcBuff,
                                           CpaBufferList *pDestBuff,
                                           CpaDcChainRqResults *pResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    /* Compression service and chain service */
    sal_compression_service_t *pDcService =
        (sal_compression_service_t *)dcInstance;
    sal_dc_chain_service_t *pChainService = pDcService->pDcChainService;
    lac_session_desc_t *pCySessDesc = NULL;
    void *pCyLinkRsp = NULL;
    Cpa64U rspDescPhyAddr = 0;
    icp_qat_fw_chain_stor2_req_t *pChainStor2Req = NULL;
    CpaCySymOpData *pCySymOp = NULL;
    pCySessDesc = LAC_SYM_SESSION_DESC_FROM_CTX_GET(pSessionHandle);

    /* Legacy CpaCySymOpData. CY OpData extensions are not supported. */
    if (CY_OPDATA_TYPE0 == pCySymOpExt->opDataType)
    {
        pCySymOp = (CpaCySymOpData *)pCySymOpExt->pOpData;
    }
    else
    {
        pCySymOp = &((CpaCySymOpData2 *)pCySymOpExt->pOpData)->symOpData;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pCySymOp);
    LAC_CHECK_NULL_PARAM(pResults);

    LAC_CHECK_STATEMENT_LOG(
        (pCySymOp->packetType == CPA_CY_SYM_PACKET_TYPE_PARTIAL ||
         pCySymOp->packetType == CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL),
        "%s",
        "Symmetric crypto partial packet are not supported in dc-chain "
        "operation.\n");

    if ((!pCySessDesc->digestIsAppended) &&
        ((CPA_CY_SYM_OP_ALGORITHM_CHAINING == pCySessDesc->symOperation) ||
         (CPA_CY_SYM_OP_HASH == pCySessDesc->symOperation)))
    {
        /* Check that pDigestResult is not NULL */
        LAC_CHECK_NULL_PARAM(pCySymOp->pDigestResult);
    }

    if (CPA_STATUS_SUCCESS !=
        dcChainSession_CheckCySessDesc(pCySessDesc, operation))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
    pCySymOp->sessionCtx = pSessionHandle;

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Add DC Chaining info to the CY cookie */
        pCyCookie->dcChain.isDcChaining = CPA_TRUE;

        /* This is the common CY function to create the requests for
         * crypto operations. It creates the crypto request
         * message but does not send it for DC chained requests. */
        status = LacAlgChain_Perform(dcInstance,
                                     pCySessDesc,
                                     NULL,
                                     pCySymOp,
                                     pCyCookie,
                                     pSrcBuff,
                                     pDestBuff,
                                     &pResults->verifyResult);
    }
    LAC_CHECK_STATUS(status);

    pCyLinkRsp = Lac_MemPoolEntryAlloc(pChainService->dc_chain_serv_resp_pool);
    if (NULL == pCyLinkRsp)
    {
        return CPA_STATUS_RESOURCE;
    }
    else if ((void *)CPA_STATUS_RETRY == pCyLinkRsp)
    {
        return CPA_STATUS_RETRY;
    }

    rspDescPhyAddr = (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
        pDcService->generic_service_info, pCyLinkRsp);
    pChainCookie->pCyRspAddr = pCyLinkRsp;
    pChainCookie->pCyCookieAddr = pCyCookie;

        pChainStor2Req = (icp_qat_fw_chain_stor2_req_t *)&pChainCookie->request;
        pChainStor2Req->symCryptoReqAddr =
            (icp_qat_addr_width_t)LAC_OS_VIRT_TO_PHYS_EXTERNAL(
                pDcService->generic_service_info, &pCyCookie->qatMsg);
        pChainStor2Req->symCryptoRespAddr = rspDescPhyAddr;

    return status;
}

/* Free memory */
STATIC void dcChainOp_MemPoolEntryFree(void *pEntry)
{
    if ((void *)CPA_STATUS_RETRY == pEntry)
        return;

    if (NULL != pEntry)
        Lac_MemPoolEntryFree(pEntry);

    return;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Chaining perform operation
 *
 * @description
 *      Chaining perform operation, it is called at cpaDcChainPerformOp,
 *      which is used to perform chaining requests.
 *
 * @param[in]       dcInstance         Instance handle derived from discovery
 *                                     functions.
 * @param[in]       pSessionHandle     Pointer to a session handle.
 * @param[in]       pSrcBuff           Source buffer
 * @param[in]       pDestBuff          Destination buffer
 * @param[in]       pInterBuff         Pointer to intermediate buffer to be
 *                                     used as internal staging area for
 *                                     chaining operations.
 * @param[in]       operation          Chaining operation type
 * @param[in]       numOperations      Number of operations for the chaining
 * @param[in]       pChainOpDataExt    Extensible chaining operation data
 * @param[in,out]   pResultsExt        Extensible chaining response result
 * @param[in]       callbackTag        For synchronous operation this callback
 *                                     shall be a null pointer.
 *
 * @retval CPA_STATUS_SUCCESS        Function executed successfully
 * @retval CPA_STATUS_FAIL           Function failed to find device
 * @retval CPA_STATUS_INVALID_PARAM  Invalid parameter passed in
 * @retval CPA_STATUS_RESOURCE       Failed to allocate required resources
 * @retval CPA_STATUS_RETRY          Request re-submission needed
 *
 *****************************************************************************/
CpaStatus dcChainPerformOp(CpaInstanceHandle dcInstance,
                           CpaDcSessionHandle pSessionHandle,
                           CpaBufferList *pSrcBuff,
                           CpaBufferList *pDestBuff,
                           CpaBufferList *pInterBuff,
                           CpaDcChainOperations operation,
                           Cpa8U numOperations,
                           dc_chain_opdata_ext_t *pChainOpDataExt,
                           dc_chain_results_ext_t *pResultsExt,
                           void *callbackTag)

{
    CpaInstanceHandle insHandle = NULL;
    /* Compression service and chain service */
    sal_compression_service_t *pDcService = NULL;
    ;
    sal_dc_chain_service_t *pChainService;
    /* Session descriptor for compression and crypto */
    dc_session_desc_t *pDcSessDesc = NULL;
    dc_chain_session_head_t *pSessHead = NULL;
    /* Cookies for chaining (compression + crypto) */
    dc_chain_cookie_t *pChainCookie = NULL;
    dc_compression_cookie_t *pDcCookie = NULL;
    lac_sym_bulk_cookie_t *pCyCookie = NULL;
    /* Request for chaining (compression + crypto) */
    icp_qat_fw_chain_stor2_req_t *pChainStor2Req = NULL;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U *pTemp;
    Cpa32U i;
    CpaBufferList *pChainSrcBuff = NULL;
    CpaBufferList *pChainDestBuff = NULL;
    CpaDcChainOpData *pChainSubOpData = NULL;
    CpaDcChainSubOpData2 *pChainSubOpData2 = NULL;
    dc_opdata_ext_t dcOpDataExt = { 0 };
    cy_opdata_ext_t cyOpDataExt = { 0 };
    CpaDcChainRqResults *pResults = NULL;

    if (CPA_INSTANCE_HANDLE_SINGLE == dcInstance)
    {
        insHandle = dcGetFirstHandle();
    }
    else
    {
        insHandle = dcInstance;
    }

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pSessionHandle);
    LAC_CHECK_NULL_PARAM(pSrcBuff);
    LAC_CHECK_NULL_PARAM(pDestBuff);
    LAC_CHECK_NULL_PARAM(insHandle);
    LAC_CHECK_NULL_PARAM(pResultsExt);
    LAC_CHECK_NULL_PARAM(pChainOpDataExt);
    SAL_CHECK_ADDR_TRANS_SETUP(insHandle);
    SAL_CHECK_INSTANCE_TYPE(insHandle, SAL_SERVICE_TYPE_COMPRESSION);
    if (CPA_STATUS_SUCCESS != dcChainSession_CheckChainSessDesc(
                                  (dc_chain_session_head_t *)pSessionHandle,
                                  insHandle,
                                  operation,
                                  numOperations))
    {
        return CPA_STATUS_INVALID_PARAM;
    }
#endif
    pDcService = (sal_compression_service_t *)insHandle;

    /* Check if SAL is initialised otherwise return an error */
    SAL_RUNNING_CHECK(insHandle);

    pChainService = pDcService->pDcChainService;
    pSessHead = (dc_chain_session_head_t *)pSessionHandle;
    /* Allocate chaining cookie */
    pChainCookie = (dc_chain_cookie_t *)Lac_MemPoolEntryAlloc(
        pChainService->dc_chain_cookie_pool);
    if (NULL == pChainCookie)
    {
        return CPA_STATUS_RESOURCE;
    }
    else if ((void *)CPA_STATUS_RETRY == pChainCookie)
    {
        return CPA_STATUS_RETRY;
    }

    if (DC_CHAIN_OPDATA_TYPE0 == pChainOpDataExt->opDataType)
    {
        pChainSubOpData = (CpaDcChainOpData *)pChainOpDataExt->pOpData;
    }
    else
    {
        pChainSubOpData2 =
            ((CpaDcChainOpData2 *)pChainOpDataExt->pOpData)->pChainOpData;
    }

    if (DC_CHAIN_RESULTS_TYPE0 == pResultsExt->resultsType)
    {
        pResults = (CpaDcChainRqResults *)pResultsExt->pResults;
    }
    else
    {
        pResults =
            &((CpaDcChainRqVResults *)pResultsExt->pResults)->chainRqResults;
    }

    /* Populate chaining cookie */
    LAC_OS_BZERO(pChainCookie, sizeof(dc_chain_cookie_t));
    pChainCookie->dcInstance = insHandle;
    pChainCookie->pSessionHandle = pSessionHandle;
    pChainCookie->extResults = *pResultsExt;
    pChainCookie->callbackTag = callbackTag;

    /* Build chaining common header */
        pChainStor2Req = (icp_qat_fw_chain_stor2_req_t *)&pChainCookie->request;
        LAC_OS_BZERO(pChainStor2Req, sizeof(icp_qat_fw_chain_stor2_req_t));

        /* Populates the QAT common request header part of the message
         * (LW 0 to 1) */
        osalMemCopy((void *)(&pChainStor2Req->comn_hdr),
                    (void *)(&pSessHead->hdr.comn_hdr2),
                    sizeof(icp_qat_fw_comn_req_hdr_t));

    osalAtomicInc(&(pSessHead->pendingChainCbCount));
    pTemp = (Cpa8U *)pSessionHandle + sizeof(dc_chain_session_head_t);
    for (i = 0; i < numOperations; i++)
    {
        /* Use chaining intermediate buffer if provided. */
        if (NULL == pInterBuff)
        {
            pChainSrcBuff = pSrcBuff;
            pChainDestBuff = pDestBuff;
        }
        else
        {
            /* First chain operation */
            if (FIRST_DC_CHAIN_ITEM == i)
            {
                /* First chain operation is from pSrcBuff => pInterBuff */
                pChainSrcBuff = pSrcBuff;
                pChainDestBuff = pInterBuff;
            }
            else
            {
                /* Next chain operation is from pInterBuff => pDestBuff */
                pChainSrcBuff = pInterBuff;
                pChainDestBuff = pDestBuff;
            }
        }

        if (DC_CHAIN_TYPE_GET(pTemp) == CPA_DC_CHAIN_COMPRESS_DECOMPRESS)
        {
            pTemp += sizeof(CpaDcChainSessionType);
            pDcSessDesc = DC_SESSION_DESC_FROM_CTX_GET(pTemp);
            pDcCookie = (dc_compression_cookie_t *)Lac_MemPoolEntryAlloc(
                pDcService->compression_mem_pool);
            if (NULL == pDcCookie)
            {
                status = CPA_STATUS_RESOURCE;
                goto out_err;
            }
            else if ((void *)CPA_STATUS_RETRY == pDcCookie)
            {
                status = CPA_STATUS_RETRY;
                goto out_err;
            }

            pDcCookie->srcTotalDataLenInBytes = 0;
            if (DC_CHAIN_OPDATA_TYPE0 == pChainOpDataExt->opDataType)
            {
                dcOpDataExt.opDataType = DC_OPDATA_TYPE0;
                dcOpDataExt.pOpData = pChainSubOpData[i].pDcOp;

                /* For Decrypt/Decompress operations, we get the number of bytes
                 * to 'decompress' from the preceding 'decrypt' operation.
                 */
                if (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS == operation)
                {
                    if (NULL != pChainSubOpData[0].pCySymOp)
                    {
                        /* Buffer length is the output from the
                         * cipher operation */
                        pDcCookie->srcTotalDataLenInBytes =
                            pChainSubOpData[0]
                                .pCySymOp->messageLenToCipherInBytes;
                    }
                    else
                    {
                        LAC_LOG_ERROR("pCySymOp is NULL\n");
                        status = CPA_STATUS_INVALID_PARAM;
                        goto out_err;
                    }
                }
            }
            else
            {
                dcOpDataExt.opDataType = DC_OPDATA_TYPE1;
                dcOpDataExt.pOpData = pChainSubOpData2[i].pDcOp2;

                /* For Decrypt/Decompress operations, we get the number of bytes
                 * to 'decompress' from the preceding 'decrypt' operation.
                 */
                if (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS == operation)
                {
                    if (NULL != pChainSubOpData2[0].pCySymOp2)
                    {
                        /* Buffer length is the output from the
                         * cipher operation */
                        pDcCookie->srcTotalDataLenInBytes =
                            pChainSubOpData2[0]
                                .pCySymOp2->symOpData.messageLenToCipherInBytes;
                    }
                    else
                    {
                        LAC_LOG_ERROR("pCySymOp2 is NULL\n");
                        status = CPA_STATUS_INVALID_PARAM;
                        goto out_err;
                    }
                }
            }

            status = dcChainPrepare_CompRequest(insHandle,
                                                pChainCookie,
                                                operation,
                                                pTemp,
                                                &dcOpDataExt,
                                                pDcCookie,
                                                pChainSrcBuff,
                                                pChainDestBuff,
                                                pResults);
            if (CPA_STATUS_SUCCESS != status)
                goto out_err;
            pTemp += DC_COMP_SESSION_SIZE;
        }
        else
        {
            pTemp += sizeof(CpaDcChainSessionType);
            pCyCookie = (lac_sym_bulk_cookie_t *)Lac_MemPoolEntryAlloc(
                pChainService->lac_sym_cookie_pool);
            if (NULL == pCyCookie)
            {
                LAC_LOG_ERROR("Cannot get symmetric crypto mem pool entry\n");
                status = CPA_STATUS_RESOURCE;
                goto out_err;
            }
            else if ((void *)CPA_STATUS_RETRY == pCyCookie)
            {
                status = CPA_STATUS_RETRY;
                goto out_err;
            }

            if (DC_CHAIN_OPDATA_TYPE0 == pChainOpDataExt->opDataType)
            {
                cyOpDataExt.opDataType = CY_OPDATA_TYPE0;
                cyOpDataExt.pOpData = pChainSubOpData[i].pCySymOp;
            }
            else
            {
                cyOpDataExt.opDataType = CY_OPDATA_TYPE1;
                cyOpDataExt.pOpData = pChainSubOpData2[i].pCySymOp2;
            }

            status = dcChainPrepare_SymRequest(insHandle,
                                               pChainCookie,
                                               operation,
                                               pTemp,
                                               pCyCookie,
                                               &cyOpDataExt,
                                               pChainSrcBuff,
                                               pChainDestBuff,
                                               pResults);
            if (CPA_STATUS_SUCCESS != status)
                goto out_err;
            pTemp += LAC_SYM_SESSION_SIZE;
        }
    }

    if (NULL == pDcSessDesc)
    {
        LAC_LOG_ERROR("No compression request on Chaining\n");
        status = CPA_STATUS_INVALID_PARAM;
        goto out_err;
    }

        /* Populates the QAT common request middle part of the message
         * (LW 6 to 13).
         * Note: arg 3 (buffer type) should be a flat buffer type, as there
         * is a strict check for this condition in Gen6 firmware. This parameter
         * was ignored in previous generation. */
        SalQatMsg_CmnMidWrite(
            (icp_qat_fw_la_bulk_req_t *)&pChainCookie->request,
            pChainCookie,
            QAT_COMN_PTR_TYPE_FLAT,
            (Cpa64U)NULL,
            (Cpa64U)NULL,
            0,
            0);

    /*Put message on the ring*/
    status = SalQatMsg_transPutMsg(pDcService->trans_handle_compression_tx,
                                   (void *)&pChainCookie->request,
                                   LAC_QAT_DC_REQ_SZ_LW,
                                   LAC_LOG_MSG_DC,
                                   NULL);

    /*update stats*/
    if (CPA_STATUS_SUCCESS == status)
    {
        if (pDcSessDesc->sessDirection == CPA_DC_DIR_COMPRESS)
        {
            COMPRESSION_STAT_INC(numCompRequests, pDcService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequests, pDcService);
        }
    }
    else
    {
        if (pDcSessDesc->sessDirection == CPA_DC_DIR_COMPRESS)
        {
            COMPRESSION_STAT_INC(numCompRequestsErrors, pDcService);
        }
        else
        {
            COMPRESSION_STAT_INC(numDecompRequestsErrors, pDcService);
        }
        goto out_err;
    }
    return CPA_STATUS_SUCCESS;

out_err:
    osalAtomicDec(&(pSessHead->pendingChainCbCount));
    dcChainOp_MemPoolEntryFree(pDcCookie);
    dcChainOp_MemPoolEntryFree(pCyCookie);
    dcChainOp_MemPoolEntryFree(pChainCookie->pDcRspAddr);
    dcChainOp_MemPoolEntryFree(pChainCookie->pCyRspAddr);
    dcChainOp_MemPoolEntryFree(pChainCookie);
    return status;
}

CpaStatus cpaDcChainPerformOp(CpaInstanceHandle dcInstance,
                              CpaDcSessionHandle pSessionHandle,
                              CpaBufferList *pSrcBuff,
                              CpaBufferList *pDestBuff,
                              CpaDcChainOperations operation,
                              Cpa8U numOpDatas,
                              CpaDcChainOpData *pChainOpData,
                              CpaDcChainRqResults *pResults,
                              void *callbackTag)
{
    dc_chain_opdata_ext_t chainOpDataExt = { 0 };
    dc_chain_results_ext_t chainResultsExt = { 0 };

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pChainOpData);
#endif
    chainOpDataExt.opDataType = DC_CHAIN_OPDATA_TYPE0;
    chainOpDataExt.pOpData = pChainOpData;
    chainResultsExt.resultsType = DC_CHAIN_RESULTS_TYPE0;
    chainResultsExt.pResults = pResults;
    return dcChainPerformOp(dcInstance,
                            pSessionHandle,
                            pSrcBuff,
                            pDestBuff,
                            NULL,
                            operation,
                            numOpDatas,
                            &chainOpDataExt,
                            &chainResultsExt,
                            callbackTag);
}

/**
 *****************************************************************************
 * @ingroup cpaDcChain
 *      Submit a request to perform chaining with integrity operations.
 *
 * @description
 *      This function is used to perform chaining operations over data from
 *      the source buffer with optional integrity checking.
 *
 * @param[in]     dcInstance        Target service instance.
 * @param[in,out] pSessionHandle    Session handle.
 * @param[in]     pSrcBuff          Pointer to input data buffer.
 * @param[out]    pDestBuff         Pointer to output data buffer.
 * @param[in]     pInterBuff        Pointer to intermediate buffer to be used
 *                                  as internal staging area for chaining
 *                                  operations.
 * @param[in]     opData            User supplied CpaDcChainOpData2
 *                                  structure.
 * @param[in,out] pResults          Pointer to CpaDcChainRqVResults
 *                                  structure.
 * @param[in]     callbackTag       User supplied value to help correlate
 *                                  the callback with its associated request.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 * @retval CPA_STATUS_RETRY         Resubmit the request.
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in.
 * @retval CPA_STATUS_RESOURCE      Error related to system resources.
 * @retval CPA_DC_BAD_DATA          The input data was not properly formed.
 * @retval CPA_STATUS_RESTARTING    API implementation is restarting. Resubmit
 *                                  the request.
 * @retval CPA_STATUS_UNSUPPORTED   Function is not supported.
 *
 *****************************************************************************/
CpaStatus cpaDcChainPerformOp2(CpaInstanceHandle dcInstance,
                               CpaDcSessionHandle pSessionHandle,
                               CpaBufferList *pSrcBuff,
                               CpaBufferList *pDestBuff,
                               CpaBufferList *pInterBuff,
                               CpaDcChainOpData2 opData,
                               CpaDcChainRqVResults *pResults,
                               void *callbackTag)
{
    return CPA_STATUS_UNSUPPORTED;
}

/**
 ************************************************************************
 * @ingroup Dc_Chaining
 *    Process symmetric crypto response message for chaining
 *
 * @param[in]    pCyCookie        Symmetric crypto cookie
 * @param[in]    pCySessionDesc   Symmetric crypto session description
 * @param[in]    pCyRespMsg       Symmetric crypto response message
 *
 * @param[out]   pResults         Chaining request result
 *
 * @retval void
 *
 **************************************************************************/
STATIC void dcChainCallback_ProcessSymCrypto(lac_sym_bulk_cookie_t *pCyCookie,
                                             lac_session_desc_t *pCySessionDesc,
                                             icp_qat_fw_la_resp_t *pCyRespMsg,
                                             CpaDcChainRqResults *pResults)
{
    Cpa8U opStatus = ICP_QAT_FW_COMN_STATUS_FLAG_OK;
    Cpa8U comnErr = ERR_CODE_NO_ERROR;

    opStatus = pCyRespMsg->comn_resp.comn_status;
    comnErr = pCyRespMsg->comn_resp.comn_error.s.comn_err_code;
    /* Log the slice hang, ssm parity and endpoint push/pullerror inside the
     * response */
    if (ERR_CODE_SSM_ERROR == (Cpa8S)comnErr)
    {
        LAC_LOG_ERROR("Slice hang detected on CPM cipher or auth slice. ");
    }
    else if (ERR_CODE_SSM_PARITY_ERROR == (Cpa8S)comnErr)
    {
        LAC_LOG_ERROR("Operation resulted in a parity error in one or more "
                      "accelerators.");
    }
    else if (ERR_CODE_ENDPOINT_ERROR == (Cpa8S)comnErr)
    {
        LAC_LOG_ERROR(
            "The PCIe End Point Push/Pull or TI/RI Parity error detected.");
    }

    pResults->cyStatus = CPA_STATUS_FAIL;
    pResults->verifyResult = CPA_FALSE;
    if (ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
        ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(opStatus))
    {
        pResults->cyStatus = CPA_STATUS_SUCCESS;
        if (CPA_TRUE == pCySessionDesc->digestVerify)
            pResults->verifyResult = CPA_TRUE;
    }

    return;
}

/**
 ************************************************************************
 * @ingroup Dc_Chaining
 *    Process data compression response message for chaining
 *
 * @param[in]    pDcCookie        Data compression cookie
 * @param[in]    pDcSessionDesc   Data compression session description
 * @param[in]    pCompRespMsg     Data compression response message
 *
 * @param[out]   pResults         Chaining request result
 *
 * @retval CPA_STATUS_SUCCESS     Function executed successfully
 * @retval CPA_STATUS_FAIL        Function failed to find device
 *
 **************************************************************************/
STATIC CpaStatus
dcChainCallback_ProcessComp(dc_compression_cookie_t *pDcCookie,
                            dc_session_desc_t *pDcSessionDesc,
                            icp_qat_fw_comp_resp_t *pCompRespMsg,
                            CpaDcChainRqResults *pResults)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean cmpPass = CPA_TRUE, xlatPass = CPA_TRUE;
#ifndef ICP_DC_DYN_NOT_SUPPORTED
    Cpa8U xlatErr = ERR_CODE_NO_ERROR;
#endif
    Cpa8U cmpErr = ERR_CODE_NO_ERROR;
    dc_request_dir_t compDecomp = DC_COMPRESSION_REQUEST;
    Cpa8U opStatus = ICP_QAT_FW_COMN_STATUS_FLAG_OK;
    sal_compression_service_t *pService = NULL;
    Cpa8U hdrFlags = 0;

    opStatus = pCompRespMsg->comn_resp.comn_status;
    hdrFlags = pCompRespMsg->comn_resp.hdr_flags;

    /* Check compression response status */
    cmpPass = (CpaBoolean)(ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                           ICP_QAT_FW_COMN_RESP_CMP_STAT_GET(opStatus));
    pService = (sal_compression_service_t *)(pDcCookie->dcInstance);

    /* Get the cmp error code */
    cmpErr = pCompRespMsg->comn_resp.comn_error.s1.cmp_err_code;
    compDecomp = pDcCookie->compDecomp;

    if ((CPA_DC_INCOMPLETE_FILE_ERR == (Cpa8S)cmpErr) ||
        (CPA_DC_BAD_STORED_BLOCK_LEN == (Cpa8S)cmpErr))
    {
        cmpPass = CPA_TRUE;
        cmpErr = ERR_CODE_NO_ERROR;
    }

    /* Log the slice hang, ssm parity and endpoint push/pull error inside the
     * response */
    if (ERR_CODE_SSM_ERROR == (Cpa8S)cmpErr)
    {
        LAC_LOG_ERROR("The slice hang is detected on the compression slice");
    }
    else if (ERR_CODE_SSM_PARITY_ERROR == (Cpa8S)cmpErr)
    {
        LAC_LOG_ERROR("Operation resulted in a parity error in one or more "
                      "accelerators.");
    }
    else if (ERR_CODE_ENDPOINT_ERROR == (Cpa8S)cmpErr)
    {
        LAC_LOG_ERROR(
            "The PCIe End Point Push/Pull or TI/RI Parity error detected.");
    }

    pResults->dcStatus = (Cpa8S)cmpErr;

#ifndef ICP_DC_DYN_NOT_SUPPORTED
    /* Check the translator status */
    if ((DC_COMPRESSION_REQUEST == compDecomp) &&
        (CPA_DC_HT_FULL_DYNAMIC == pDcSessionDesc->huffType))
    {
        /* Check translator response status */
        xlatPass = (CpaBoolean)(ICP_QAT_FW_COMN_STATUS_FLAG_OK ==
                                ICP_QAT_FW_COMN_RESP_XLAT_STAT_GET(opStatus));

        /* Get the translator error code */
        xlatErr = pCompRespMsg->comn_resp.comn_error.s1.xlat_err_code;

        /* Return a fatal error or a potential error in the translator slice
         * if the compression slice did not return any error */
        if ((CPA_DC_OK == pResults->dcStatus) ||
            (CPA_DC_FATALERR == (Cpa8S)xlatErr))
        {
            pResults->dcStatus = (Cpa8S)xlatErr;
        }
    }
#endif

    status = pResults->dcStatus;
    /* In case of any error for an end of packet request, we need to update
     * the request type for the following request.
     */
    if (CPA_DC_FLUSH_FINAL == pDcCookie->flushFlag && cmpPass && xlatPass)
    {
        pDcSessionDesc->requestType = DC_REQUEST_FIRST;
    }
    else
    {
        pDcSessionDesc->requestType = DC_REQUEST_SUBSEQUENT;
    }

    if ((CPA_DC_STATEFUL == pDcSessionDesc->sessState) ||
        ((CPA_DC_STATELESS == pDcSessionDesc->sessState) &&
         (DC_COMPRESSION_REQUEST == compDecomp)))
    {
        /* Overflow is a valid use case for Traditional API only.
         * Stateful Overflow is supported in both compression and
         * decompression direction.
         * Stateless Overflow is supported only in compression direction.
         */
        if (CPA_DC_OVERFLOW == (Cpa8S)cmpErr)
        {
            cmpPass = CPA_TRUE;
        }

#ifndef ICP_DC_DYN_NOT_SUPPORTED
        if (CPA_DC_OVERFLOW == (Cpa8S)xlatErr)
        {
            xlatPass = CPA_TRUE;
        }
#endif
    }

    if ((CPA_TRUE == cmpPass) && (CPA_TRUE == xlatPass))
    {
        /* Extract the response from the firmware */
        pResults->consumed = pCompRespMsg->comp_resp_pars.input_byte_counter;
        pResults->produced = pCompRespMsg->comp_resp_pars.output_byte_counter;

        pDcSessionDesc->cumulativeConsumedBytes = pResults->consumed;

        pResults->crc32 = pCompRespMsg->comp_resp_pars.crc.legacy.curr_crc32;
        pResults->adler32 =
            pCompRespMsg->comp_resp_pars.crc.legacy.curr_adler_32;

        if (NULL != pService)
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
                COMPRESSION_STAT_INC(numCompCompleted, pService);
            else
                COMPRESSION_STAT_INC(numDecompCompleted, pService);
            /* Check if a CNV recovery happened and
             * increase stats counter
             */
            if ((DC_COMPRESSION_REQUEST == compDecomp) &&
                ICP_QAT_FW_COMN_HDR_CNV_FLAG_GET(hdrFlags) &&
                ICP_QAT_FW_COMN_HDR_CNVNR_FLAG_GET(hdrFlags))
            {
                COMPRESSION_STAT_INC(numCompCnvErrorsRecovered, pService);
            }
        }

        status = CPA_STATUS_SUCCESS;
    }
    else
    {
#ifdef ICP_DC_RETURN_COUNTERS_ON_ERROR
        /* Extract the response from the firmware */
        pResults->consumed = pCompRespMsg->comp_resp_pars.input_byte_counter;
        pResults->produced = pCompRespMsg->comp_resp_pars.output_byte_counter;
        pDcSessionDesc->cumulativeConsumedBytes = pResults->consumed;
#else
        pResults->consumed = 0;
        pResults->produced = 0;
#endif
        if (CPA_DC_OVERFLOW == pResults->dcStatus &&
            CPA_DC_STATELESS == pDcSessionDesc->sessState)
        {
            /* This error message will be returned only in stateless
             * decompression direction */
            LAC_LOG_ERROR(
                "Unrecoverable error: stateless overflow. You may "
                "need to increase the size of your destination buffer");
        }

        if (NULL != pService)
        {
            if (DC_COMPRESSION_REQUEST == compDecomp)
                COMPRESSION_STAT_INC(numCompCompletedErrors, pService);
            else
                COMPRESSION_STAT_INC(numDecompCompletedErrors, pService);
        }
    }

    return status;
}

STATIC void dcChainHandleChecksums(dc_compression_cookie_t *pDcCookie,
                                   CpaCrcData *crc_external,
                                   icp_qat_comp_chain_20_cmd_id_t chain_id,
                                   CpaDcChainRqResults *pResults)
{
    CpaDcRqResults pTempDcResults = { 0 };
    dc_session_desc_t *pSessionDesc =
        DC_SESSION_DESC_FROM_CTX_GET(pDcCookie->pSessionHandle);

    if (!pDcCookie->pDcOpData->integrityCrcCheck)
        return;

    pTempDcResults.status = pResults->dcStatus;
    pTempDcResults.produced = pResults->produced;
    pTempDcResults.consumed = pResults->consumed;

    dcHandleIntegrityChecksums(pDcCookie,
                               crc_external,
                               &pTempDcResults,
                               pSessionDesc->huffType,
                               pSessionDesc->compType,
                               pSessionDesc->checksumType,
                               CPA_FALSE,
                               chain_id);

    pResults->dcStatus = pTempDcResults.status;
}

/**
 *****************************************************************************
 * @ingroup Dc_Chaining
 *      Process chaining result
 *
 * @description
 *      Process chaining result, it is called at dcCompression_ProcessCallback
 *      when response type is chaining
 *
 * @param[in,out]   pRespMsg     Pointer to firmware response message
 *
 * @retval void
 *
 *****************************************************************************/
void dcChainProcessResults(void *pRespMsg)
{
    CpaStatus status = CPA_STATUS_FAIL;
    dc_chain_cookie_t *pChainCookie = NULL;
    dc_chain_session_head_t *pSessHead = NULL;
    icp_qat_fw_comp_chain_resp_t *pChainRespMsg = NULL;
    Cpa64U *pReqData = NULL;
    void *callbackTag = NULL;
    CpaDcChainRqResults *pResults = NULL;
    dc_chain_results_ext_t *pResultsExt = NULL;
    CpaDcCallbackFn pCbFunc = NULL;
    icp_qat_comp_chain_20_cmd_id_t cmd_id = ICP_QAT_FW_NO_CHAINING_20;

    icp_qat_fw_comp_resp_t *pCompRespMsg = NULL;
    dc_session_desc_t *pDcSessionDesc = NULL;
    dc_compression_cookie_t *pDcCookie = NULL;

    icp_qat_fw_la_resp_t *pCyRespMsg = NULL;
    lac_session_desc_t *pCySessionDesc = NULL;
    lac_sym_bulk_cookie_t *pCyCookie = NULL;
    Cpa8U respStatus = 0;

    pChainRespMsg = (icp_qat_fw_comp_chain_resp_t *)pRespMsg;
    LAC_MEM_SHARED_READ_TO_PTR(pChainRespMsg->opaque_data, pReqData);

#ifdef ICP_PARAM_CHECK
    LAC_ASSERT_NOT_NULL(pReqData);
#endif
    pChainCookie = (dc_chain_cookie_t *)pReqData;
    pSessHead = (dc_chain_session_head_t *)pChainCookie->pSessionHandle;
    callbackTag = pChainCookie->callbackTag;
    pDcSessionDesc = pSessHead->pDcSessionDesc;
    pCySessionDesc = pSessHead->pCySessionDesc;
    pCbFunc = pSessHead->pdcChainCb;
    pCompRespMsg =
        (icp_qat_fw_comp_resp_t *)((Cpa8U *)pChainCookie->pDcRspAddr);
    pCyRespMsg = (icp_qat_fw_la_resp_t *)((Cpa8U *)pChainCookie->pCyRspAddr);
    pResultsExt = &pChainCookie->extResults;
    if (DC_CHAIN_RESULTS_TYPE0 == pResultsExt->resultsType)
    {
        pResults = (CpaDcChainRqResults *)pResultsExt->pResults;
    }
    else
    {
        pResults =
            &((CpaDcChainRqVResults *)pResultsExt->pResults)->chainRqResults;
    }
    pDcCookie =
        (dc_compression_cookie_t *)((Cpa8U *)pChainCookie->pDcCookieAddr);
    pCyCookie = (lac_sym_bulk_cookie_t *)((Cpa8U *)pChainCookie->pCyCookieAddr);

    /* Check for unsupported request */
    respStatus = pChainRespMsg->rspStatus;
    if (ICP_QAT_FW_COMN_RESP_UNSUPPORTED_REQUEST_STAT_GET(respStatus))
    {
        if (DC_CHAIN_RESULTS_TYPE0 != pResultsExt->resultsType)
        {
            ((CpaDcChainRqVResults *)pResultsExt->pResults)->chainStatus =
                CPA_STATUS_FAIL;
        }
    }
    else
    {
        /* Check for crypto or compression errors */
        if (ICP_QAT_FW_COMN_RESP_CRYPTO_STAT_GET(respStatus) ||
            ICP_QAT_FW_COMN_RESP_CMP_STAT_GET(respStatus))
        {
            if (DC_CHAIN_RESULTS_TYPE0 != pResultsExt->resultsType)
            {
                ((CpaDcChainRqVResults *)pResultsExt->pResults)->chainStatus =
                    CPA_STATUS_FAIL;
            }
        }

        /* Process crypto response result */
        dcChainCallback_ProcessSymCrypto(
            pCyCookie, pCySessionDesc, pCyRespMsg, pResults);
        if (CPA_STATUS_SUCCESS == pResults->cyStatus)
        {
            /* Process compression response */
            status = dcChainCallback_ProcessComp(
                pDcCookie, pDcSessionDesc, pCompRespMsg, pResults);
            if (CPA_DC_OK != pResults->dcStatus &&
                (CPA_STATUS_SUCCESS == status))
            {
                status = CPA_STATUS_FAIL;
            }
        }
    }

    cmd_id = pChainCookie->request.hdr.service_cmd_id;
    dcChainHandleChecksums(
        pDcCookie, pDcCookie->pDcOpData->pCrcData, cmd_id, pResults);

    Lac_MemPoolEntryFree(pChainCookie->pDcRspAddr);
    Lac_MemPoolEntryFree(pChainCookie->pCyRspAddr);
    Lac_MemPoolEntryFree(pDcCookie);
    Lac_MemPoolEntryFree(pCyCookie);
    Lac_MemPoolEntryFree(pChainCookie);
    osalAtomicDec(&(pSessHead->pendingChainCbCount));

    /*pCbFunc can never be NULL, its default is LacSync_GenWakeupSyncCaller*/
    pCbFunc(callbackTag, status);
}
#endif

CpaStatus cpaDcChainSetCrcControlData(CpaInstanceHandle dcInstance,
                                      CpaDcSessionHandle pSessionHandle,
                                      CpaCrcControlData *pCrcControlData)
{
#ifdef ICP_TRACE
    LAC_LOG3("Called with params (0x%lx, 0x%lx, 0x%lx)\n",
             (LAC_ARCH_UINT)dcInstance,
             (LAC_ARCH_UINT)pSessionHandle,
             (LAC_ARCH_UINT)pCrcControlData);
#endif
    return CPA_STATUS_UNSUPPORTED;
}
