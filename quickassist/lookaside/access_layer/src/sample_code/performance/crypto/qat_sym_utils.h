/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifndef QAT_SYM_UTILS_H
#define QAT_SYM_UTILS_H

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_sample_code_crypto_utils.h"

CpaStatus qatFreeSymLists(CpaBufferList **srcBufferListArray,
                          CpaBufferList **copyBufferListArray,
                          CpaCySymOpData **encryptOpData,
                          CpaCySymOpData **decryptOpData);

CpaStatus qatAllocateSymLists(symmetric_test_params_t *setup,
                              CpaBufferList **srcBufferListArray,
                              CpaBufferList **copyBufferListArray,
                              CpaCySymOpData **encryptOpData,
                              CpaCySymOpData **decryptOpData);

CpaStatus qatFreeSymFlatBuffers(symmetric_test_params_t *setup,
                                CpaBufferList *srcBufferListArray,
                                CpaBufferList *copyBufferListArray);

CpaStatus qatAllocateSymFlatBuffers(
    symmetric_test_params_t *setup,
    CpaBufferList *srcBufferListArray,
    Cpa32U numBuffersInSrcList,     /* affects the metaSize of CpaBufferList */
    Cpa32U *sizeOfBuffersInSrcList, /* size of CpaFlatBuffers to allocate   */
    Cpa32U digestSize,
    CpaBufferList *copyBufferListArray);

CpaStatus qatSymSessionInit(symmetric_test_params_t *setup,
                            CpaCySymSessionCtx *encryptSessionCtx,
                            CpaCySymSessionCtx *decryptSessionCtx,
                            CpaCySymCbFunc pSymCb);

CpaStatus qatSymSessionTeardown(symmetric_test_params_t *setup,
                                CpaCySymSessionCtx *encryptSessionCtx,
                                CpaCySymSessionCtx *decryptSessionCtx);

CpaStatus qatSymFreeOpData(symmetric_test_params_t *const pSetup,
                           CpaCySymOpData *const pOpdata);

CpaStatus qatSymOpDataSetup(symmetric_test_params_t *pSetup,
                            CpaCySymSessionCtx sessionCtx,
                            Cpa32U *pPacketSize,
                            CpaCySymOpData *pOpdata,
                            CpaBufferList *pBuffListArray);

CpaStatus qatSymPerform(symmetric_test_params_t *setup,
                        CpaCySymOpData *ppOpData,
                        CpaBufferList *ppSrcBuffListArray);
#endif /* QAT_SYM_UTILS_H */
