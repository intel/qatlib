/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/

/*
 * This is sample code that demonstrates usage of the dc chain API,
 * and specifically using this API to perform hash plus compression chain
 * operation.
 */

#include "cpa.h"
#include "cpa_cy_sym.h"
#include "cpa_dc.h"
#include "cpa_dc_chain.h"
#include "cpa_sample_utils.h"

/* SAL hardcoded CRC parameters. Used in verification flow
 * when useHardCodedCrc is enabled
 * 0x42f0e1eba9ea3693ULL - polynomial
 * 0x0ULL - initialValue
 * 0x0 - reflectIn
 * 0x0 - reflectOut
 * 0x0ULL - xorOut
 */
#define HC_KEYCONTEXT_CRC64 0x8c051c844b2ac92aULL
#define HC_DC_COMPRESS_CRC64 0xbbdaff3b554c96fcULL
#define HC_SRC_INPUT_CRC64 0x18bea8299f01f41cULL

#define PC_KEYCONTEXT_CRC64 0x3561d50aef618effULL
#define PC_DC_COMPRESS_CRC64 0x57d08bac40e1127eULL
#define PC_SRC_INPUT_CRC64 0x47dc490fc9c462dbULL

/* Programmable CRC parameters to use */
static CpaCrcControlData progCrcControlData = {
    /**< polynomial */
    0x239c9357ac3eccd3ULL,
    /**< initialValue */
    0x6386926455673254ULL,
    /**< reflectIn */
    0x1,
    /**< reflectOut */
    0x1,
    /**< xorOut */
    0x9465776698231213ULL
};

extern int gDebugParam;
extern int useHardCodedCrc;
extern int useXstorExtensions;

/* Size in bytes of the crc appended to the compressed image */
#define DC_APPEND_CRC_SIZE_IN_BYTES (8)

#define SAMPLE_MAX_BUFF (1024)
#define TIMEOUT_MS (5000) /* 5 seconds */
#define NUM_SESSIONS_TWO (2)

/* Used by ZLIB */
#define DEFLATE_DEF_WINBITS (15)

#define TAG_LENGTH (16)
#define AES_BLOCK_SIZE (16)

/* Key Context structure definitions */
#define QATZIP_GCM_IV_SIZE_IN_BYTES (12)
#define QZ_KDF_INPUT_SIZE_IN_BYTES (128)

/* Maximum number of possible byte values */
#define MAX_NUM_BYTE_VALUES (256)

typedef enum Qz_SHASz_E
{
    QZ_SHA1_128 = 128,
    QZ_SHA2_256 = 256,
    QZ_SHA2_512 = 512
} QzSHASz_T;

typedef struct QzKDFIn_S
{
    Cpa8U derive;
    /**< flag for keymaterial or key */
    Cpa8U keyMaterial[(QZ_SHA2_256 / 8) + QZ_KDF_INPUT_SIZE_IN_BYTES];
    /**< concatenation of keyin and (n,label,0x00,context,hash_sz)
     * < hash_sz represents the number of bytes produced with the
     * < hmac hash operation. Currently, only QZ_SHA2_256 is supported */
    Cpa8U keyinLen;
    /**< length of keyin octets */
    Cpa8U concatLen;
    /**< length of ((n,label,0x00,context,hmac_sz)
     * < Note: concateLen does not include the length of the input key */
} QzKDFIn_T;

typedef struct QzStor2KM_S
{
    QzKDFIn_T p_km1;
    /**< Key material */
    QzKDFIn_T p_km2;
    /**< not used if verify = 0 */
    Cpa8U p_iv[QATZIP_GCM_IV_SIZE_IN_BYTES];
    /**< IV */
} QzStor2KM_T;

/* Key context structure which contains 2 key materials (p_km1/p_km2) */
static QzStor2KM_T sampleKeyContext = {
    { 0x01,
      { 0x3a, 0x68, 0x2c, 0x3a, 0x5d, 0xd2, 0xcb, 0xc1, 0x38, 0x31, 0xb9, 0xfe,
        0x80, 0xb2, 0x61, 0xd0, 0x61, 0x6b, 0xc4, 0x22, 0x1d, 0x74, 0xc7, 0xa9,
        0x25, 0x09, 0x84, 0xeb, 0x53, 0x73, 0x01, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x6c, 0x61, 0x62, 0x65, 0x6c, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 },
      0x20,
      0x1e },
    { 0x01,
      { 0x3a, 0x68, 0x2c, 0x3a, 0x5d, 0xd2, 0xcb, 0xc1, 0x38, 0x31, 0xb9, 0xfe,
        0x80, 0xb2, 0x61, 0xd0, 0x61, 0x6b, 0xc4, 0x22, 0x1d, 0x74, 0xc7, 0xa9,
        0x25, 0x09, 0x84, 0xeb, 0x53, 0x73, 0x01, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x6c, 0x61, 0x62, 0x65, 0x6c, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00 },
      0x20,
      0x1e },
    { 0x52, 0x9b, 0xfd, 0x2a, 0xbb, 0xb3, 0xbb, 0x64, 0x8f, 0x9f, 0x43, 0xf9 }
};

static Cpa8U sampleAddAuthData[] = { 0xde, 0xad, 0xde, 0xad, 0xde, 0xad, 0xde,
                                     0xad, 0xde, 0xad, 0xde, 0xad, 0xde, 0xad,
                                     0xde, 0xad, 0xde, 0xad, 0xde, 0xad };

static Cpa8U samplePayload[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36,
    0x45, 0x64, 0xab, 0xd5, 0x27, 0x4a, 0xcb, 0xbb, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xEF, 0xEF, 0xEF,
    0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36, 0x45, 0x64, 0xab, 0xd5,
    0x27, 0x4a, 0xcb, 0xbb, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68,
    0x76, 0x34, 0x65, 0x36, 0x45, 0x64, 0xab, 0xd5, 0x27, 0x4a, 0xcb, 0xbb,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
    0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xDE, 0xAD, 0xEE, 0xEE,
    0xDE, 0xAD, 0xBB, 0xBF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0xEF, 0xEF, 0xEF, 0x34, 0x53, 0x84, 0x68, 0x76, 0x34, 0x65, 0x36,
    0x45, 0x64, 0xab, 0xd5, 0x27, 0x4A, 0xCB, 0xBB
};

/* AES key, 256 bits long. Derived from the above sampleKeyContext */
static Cpa8U ctxSampleKey[] = {
    0x09, 0x96, 0xb0, 0xda, 0x0e, 0xac, 0xbe, 0x73, 0x7d, 0x2e, 0xaf,
    0xa5, 0x88, 0x95, 0x05, 0xca, 0x64, 0xb4, 0x66, 0x57, 0xcb, 0xe1,
    0xdf, 0x14, 0xd4, 0x71, 0x03, 0xbe, 0x1b, 0xc4, 0x7f, 0x7a
};

/* IV contained in the above sampleKeyContext */
static Cpa8U ctxSampleIv[] = { 0x52, 0x9b, 0xfd, 0x2a, 0xbb, 0xb3,
                               0xbb, 0x64, 0x8f, 0x9f, 0x43, 0xf9 };

static Cpa32U cipherSizeInBytes = 0;

static void dcChainFreeBufferList(CpaBufferList **testBufferList);

/* Copy multiple buffers data in buffer lists to flat buffer */
static void copyMultiFlatBufferToBuffer(CpaBufferList *pBufferListSrc,
                                        Cpa8U *pBufferDst)
{
    int i = 0;
    int offset = 0;
    CpaFlatBuffer *pBuffers = pBufferListSrc->pBuffers;

    for (; i < pBufferListSrc->numBuffers; i++)
    {
        memcpy(pBufferDst + offset, pBuffers->pData, pBuffers->dataLenInBytes);
        offset += pBuffers->dataLenInBytes;
        pBuffers++;
    }
}

/*
 * Callback function
 *
 * This function is "called back" (invoked by the implementation of
 * the API) when the asynchronous operation has completed.  The
 * context in which it is invoked depends on the implementation, but
 * as described in the API it should not sleep (since it may be called
 * in a context which does not permit sleeping, e.g. a Linux bottom
 * half).
 *
 * This function can perform whatever processing is appropriate to the
 * application.  For example, it may free memory, continue processing
 * of a packet, etc.  In this example, the function only sets the
 * complete variable to indicate it has been called.
 */
//<snippet name="dcCallback">
static void dcCallback(void *pCallbackTag, CpaStatus status)
{
    PRINT_DBG("Callback called with status = %d.\n", status);

    if (NULL != pCallbackTag)
    {
        /* indicate that the function has been called */
        COMPLETE((struct COMPLETION_STRUCT *)pCallbackTag);
    }
}
//</snippet>

/* Build dc chain buffer lists */
static CpaStatus dcChainBuildBufferList(CpaBufferList **testBufferList,
                                        Cpa32U numBuffers,
                                        Cpa32U bufferSize,
                                        Cpa32U bufferMetaSize)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBufferList *pBuffList = NULL;
    CpaFlatBuffer *pFlatBuff = NULL;
    Cpa32U curBuff = 0;
    Cpa8U *pMsg = NULL;
    /*
     * allocate memory for bufferlist and array of flat buffers in a contiguous
     * area and carve it up to reduce number of memory allocations required.
     */
    Cpa32U bufferListMemSize =
        sizeof(CpaBufferList) + (numBuffers * sizeof(CpaFlatBuffer));

    status = OS_MALLOC(&pBuffList, bufferListMemSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error in allocating pBuffList\n");
        return CPA_STATUS_FAIL;
    }

    pBuffList->numBuffers = numBuffers;

    if (bufferMetaSize)
    {
        status =
            PHYS_CONTIG_ALLOC(&pBuffList->pPrivateMetaData, bufferMetaSize);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Error in allocating pBuffList->pPrivateMetaData\n");
            OS_FREE(pBuffList);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        pBuffList->pPrivateMetaData = NULL;
    }

    pFlatBuff = (CpaFlatBuffer *)(pBuffList + 1);
    pBuffList->pBuffers = pFlatBuff;

    while (curBuff < numBuffers)
    {
        if (0 != bufferSize)
        {
            status = PHYS_CONTIG_ALLOC(&pMsg, bufferSize);
            if (CPA_STATUS_SUCCESS != status || NULL == pMsg)
            {
                PRINT_ERR("Error in allocating pMsg\n");
                dcChainFreeBufferList(&pBuffList);
                return CPA_STATUS_FAIL;
            }
            memset(pMsg, 0, bufferSize);
            pFlatBuff->pData = pMsg;
        }
        else
        {
            pFlatBuff->pData = NULL;
        }
        pFlatBuff->dataLenInBytes = bufferSize;
        pFlatBuff++;
        curBuff++;
    }

    *testBufferList = pBuffList;

    return CPA_STATUS_SUCCESS;
}

/* Free dc chain buffer lists */
static void dcChainFreeBufferList(CpaBufferList **testBufferList)
{
    CpaBufferList *pBuffList = *testBufferList;
    CpaFlatBuffer *pFlatBuff = NULL;
    Cpa32U curBuff = 0;

    if (NULL == pBuffList)
    {
        PRINT_ERR("testBufferList is NULL\n");
        return;
    }

    pFlatBuff = pBuffList->pBuffers;
    while (curBuff < pBuffList->numBuffers)
    {
        if (NULL != pFlatBuff->pData)
        {
            PHYS_CONTIG_FREE(pFlatBuff->pData);
            pFlatBuff->pData = NULL;
        }
        pFlatBuff++;
        curBuff++;
    }

    if (NULL != pBuffList->pPrivateMetaData)
    {
        PHYS_CONTIG_FREE(pBuffList->pPrivateMetaData);
        pBuffList->pPrivateMetaData = NULL;
    }

    OS_FREE(pBuffList);
    *testBufferList = NULL;
}

/*
 * This function performs a software verification of the QAT HW Chain Operation.
 */
static CpaStatus dcChainingVerify(void *pSrcBuffer,
                                  Cpa32U srcBufferSize,
                                  void *pExpectedBuffer,
                                  Cpa32U expectedBufferSize,
                                  CpaBoolean appendedCrc,
                                  CpaBoolean verifyKeyContext,
                                  CpaDcChainRqVResults *chainResult,
                                  CpaDcChainOpData2 *pChainOpData2,
                                  CpaCrcData *pCrcDataBuffer)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa64U keyContextCrc;
    Cpa64U srcInputCrc;
    if (useHardCodedCrc)
    {
        keyContextCrc = HC_KEYCONTEXT_CRC64;
        srcInputCrc = HC_SRC_INPUT_CRC64;
    }
    else
    {
        keyContextCrc = PC_KEYCONTEXT_CRC64;
        srcInputCrc = PC_SRC_INPUT_CRC64;
    }

    if (verifyKeyContext && (keyContextCrc != chainResult->ctxCrc64))
    {
        PRINT_ERR("pKeyContext: 0x%lx  Expected CRC64: 0x%lx\n",
                  chainResult->ctxCrc64,
                  keyContextCrc);
        status = CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        if (pChainOpData2->operation == CPA_DC_CHAIN_COMPRESS_THEN_AEAD)
        {
            if (appendedCrc)
            {
                /* Check that CRC64 appended to the image matches
                 * expected image CRC64 */
                if (srcInputCrc != chainResult->iDcCrc64)
                {
                    status = CPA_STATUS_FAIL;
                    PRINT_ERR("iDcCrc64: 0x%lx  Expected CRC64: "
                              "0x%lx\n",
                              chainResult->iDcCrc64,
                              srcInputCrc);
                }
            }

            if (srcInputCrc != pCrcDataBuffer->integrityCrc64b.iCrc)
            {
                PRINT_ERR("pCrcDataBuffer->integrityCrc64b.iCrc: 0x%lx  "
                          "Expected CRC64: 0x%lx\n",
                          pCrcDataBuffer->integrityCrc64b.iCrc,
                          srcInputCrc);
                status = CPA_STATUS_FAIL;
            }
        }
        else
        {
            /* Compare Cleartext sample buffer with QAT HW decrypt/decompress
             * buffer
             */
            if (memcmp(pSrcBuffer, pExpectedBuffer, expectedBufferSize))
            {
                status = CPA_STATUS_FAIL;
                PRINT_ERR("Hardware decrypt/decompress buffer does not match "
                          "source buffer\n");
            }
            else
            {
                if (appendedCrc &&
                    (chainResult->storedCrc64 != chainResult->oDcCrc64))
                {
                    status = CPA_STATUS_FAIL;
                    PRINT_ERR("Stored CRC64: 0x%lx  Expected CRC64: 0x%lx\n",
                              chainResult->storedCrc64,
                              chainResult->oDcCrc64);
                }
                else
                {
                    PRINT_DBG(
                        "Hardware decrypt/decompress buffer matches source "
                        "buffer\n");
                }
            }
        }
    }
    return status;
}
/*
 * This function performs a dc chain operation.
 */
static CpaStatus dcChainingPerformOp(CpaInstanceHandle dcInstHandle,
                                     CpaDcSessionHandle sessionHdl,
                                     CpaDcChainOperations operation,
                                     void *pSrcBuffer,
                                     Cpa32U srcBufferSize,
                                     void *pDstBuffer,
                                     Cpa32U dstBufferSize,
                                     Cpa32U intermediateBufferSize,
                                     Cpa8U *pDigestBuffer,
                                     CpaBoolean testIntegrity)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U bufferMetaSize = 0;
    CpaBufferList *pBufferListSrc = NULL;
    CpaBufferList *pBufferListDst = NULL;
    CpaBufferList *pBufferListIntermediate = NULL;
    CpaFlatBuffer *pFlatBuffer = NULL;
    Cpa32U numBuffers = 1;
    CpaDcChainSubOpData2 chainOpData[2] = { { 0 }, { 0 } };
    CpaDcOpData2 dcOpData2 = { 0 };
    CpaCySymOpData2 cySymOpData2 = { 0 };
    CpaDcChainRqVResults chainResult = { 0 };
    Cpa8U numSessions = NUM_SESSIONS_TWO;
    struct COMPLETION_STRUCT complete;
    Cpa32U aadBuffSize = 0;
    Cpa8U *pAadBuffer = NULL;
    CpaDcChainOpData2 dcChainOpData2;
    Cpa8U *pContextBuffer = NULL;
    CpaCrcData *pCrcDataBuffer = NULL;
    CpaBoolean appendedCrc = CPA_FALSE;
    Cpa8U *pIvBuffer = NULL;
    CpaBoolean verifyKeyContext = CPA_FALSE;

    PRINT_DBG("cpaDcBufferListGetMetaSize\n");

    /*
     * Different implementations of the API require different
     * amounts of space to store meta-data associated with buffer
     * lists.  We query the API to find out how much space the current
     * implementation needs, and then allocate space for the buffer
     * meta data, the buffer list, and for the buffer itself.
     */
    //<snippet name="memAlloc">
    status =
        cpaDcBufferListGetMetaSize(dcInstHandle, numBuffers, &bufferMetaSize);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Error get meta size\n");
        return CPA_STATUS_FAIL;
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainBuildBufferList(
            &pBufferListSrc, numBuffers, srcBufferSize, bufferMetaSize);
    }

    /* copy source data into buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        pFlatBuffer = (CpaFlatBuffer *)(pBufferListSrc + 1);
        memcpy(pFlatBuffer->pData, pSrcBuffer, srcBufferSize);
    }

    /* Allocate destination buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainBuildBufferList(
            &pBufferListDst, numBuffers, dstBufferSize, bufferMetaSize);
    }

    /* Create an intermediate buffer to be used as an internal staging area
     * for chain operations. The size of this buffer must match the size of
     * the destination buffer used for the crypto part of the DC Chain.
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = dcChainBuildBufferList(&pBufferListIntermediate,
                                        numBuffers,
                                        intermediateBufferSize,
                                        bufferMetaSize);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate memory for AAD. For GCM this memory will hold the
         * additional authentication data and any padding to ensure total
         * size is a multiple of the AES block size
         */
        aadBuffSize = sizeof(sampleAddAuthData);
        if (aadBuffSize % AES_BLOCK_SIZE)
        {
            aadBuffSize += AES_BLOCK_SIZE - (aadBuffSize % AES_BLOCK_SIZE);
        }
        status = PHYS_CONTIG_ALLOC(&pAadBuffer, aadBuffSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            memcpy(pAadBuffer, sampleAddAuthData, sizeof(sampleAddAuthData));
        }
    }

    /* Create the key context buffer */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pContextBuffer, sizeof(sampleKeyContext));

        if (CPA_STATUS_SUCCESS == status)
        {
            memcpy(pContextBuffer, &sampleKeyContext, sizeof(sampleKeyContext));
        }
    }

    if (!useXstorExtensions)
    {
        /* Create the IV buffer */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pIvBuffer, AES_BLOCK_SIZE);
            if (CPA_STATUS_SUCCESS == status)
            {
                memcpy(pIvBuffer, ctxSampleIv, sizeof(ctxSampleIv));
            }
        }
    }

    /* Create the E2E CRC data structure */
    if (CPA_STATUS_SUCCESS == status)
    {
        status = PHYS_CONTIG_ALLOC(&pCrcDataBuffer, sizeof(CpaCrcData));

        if (CPA_STATUS_SUCCESS == status)
        {
            memset(pCrcDataBuffer, 0, sizeof(CpaCrcData));
        }
    }

    //</snippet>
    if (CPA_STATUS_SUCCESS == status)
    {
        dcOpData2.dcOpData.flushFlag = CPA_DC_FLUSH_FINAL;
        dcOpData2.dcOpData.compressAndVerify = CPA_TRUE;
        dcOpData2.dcOpData.compressAndVerifyAndRecover = CPA_FALSE;
        dcOpData2.dcOpData.integrityCrcCheck = CPA_TRUE;
        dcOpData2.dcOpData.verifyHwIntegrityCrcs = CPA_FALSE;
        dcOpData2.dcOpData.pCrcData = pCrcDataBuffer;
        if (useXstorExtensions)
        {
            dcOpData2.appendCRC64 = CPA_TRUE;
        }
        else
        {
            dcOpData2.appendCRC64 = CPA_FALSE;
        }
        cySymOpData2.symOpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
        cySymOpData2.symOpData.cryptoStartSrcOffsetInBytes = 0;
        cySymOpData2.symOpData.messageLenToCipherInBytes = cipherSizeInBytes;
        cySymOpData2.symOpData.pAdditionalAuthData = pAadBuffer;
        cySymOpData2.symOpData.pDigestResult = pDigestBuffer;
        if (useXstorExtensions)
        {
            cySymOpData2.symOpData.pIv = NULL;
            cySymOpData2.symOpData.ivLenInBytes = 0;
            cySymOpData2.deriveCtxData.pContext = pContextBuffer;
            cySymOpData2.deriveCtxData.contextLen = sizeof(sampleKeyContext);
        }
        else
        {
            cySymOpData2.symOpData.pIv = pIvBuffer;
            cySymOpData2.symOpData.ivLenInBytes = sizeof(ctxSampleIv);
            cySymOpData2.deriveCtxData.pContext = NULL;
            cySymOpData2.deriveCtxData.contextLen = 0;
        }

        /* copy source into buffer */
        if (CPA_DC_CHAIN_COMPRESS_THEN_AEAD == operation)
        {
            /* Set chaining operation data */
            chainOpData[0].opType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            chainOpData[0].pDcOp2 = &dcOpData2;
            chainOpData[1].opType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            chainOpData[1].pCySymOp2 = &cySymOpData2;
        }
        else
        {
            /* Set chaining operation data */
            chainOpData[0].opType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
            chainOpData[0].pCySymOp2 = &cySymOpData2;
            chainOpData[1].opType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
            chainOpData[1].pDcOp2 = &dcOpData2;
        }

        /*
         * Now, we initialize the completion variable which is used by the
         * callback function to indicate that the operation is complete.
         * We then perform the operation.
         */
        //<snippet name="perfOp">
        COMPLETION_INIT(&complete);
        if (useXstorExtensions && testIntegrity)
        {
            dcChainOpData2.testIntegrity = CPA_TRUE;
        }
        else
        {
            dcChainOpData2.testIntegrity = CPA_FALSE;
        }

        dcChainOpData2.operation = operation;
        dcChainOpData2.numOpDatas = numSessions;
        dcChainOpData2.pChainOpData = chainOpData;
        status = cpaDcChainPerformOp2(dcInstHandle,
                                      sessionHdl,
                                      pBufferListSrc,
                                      pBufferListDst,
                                      pBufferListIntermediate,
                                      dcChainOpData2,
                                      &chainResult,
                                      (void *)&complete);
        //</snippet>

        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcChainPerformOp2 failed. (status = %d)\n", status);
        }

        /*
         * We now wait until the completion of the operation.  This uses a macro
         * which can be defined differently for different OSes.
         */
        if (CPA_STATUS_SUCCESS == status)
        {
            if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))
            {
                PRINT_ERR("timeout or interruption in cpaDcChainPerformOp2\n");
                status = CPA_STATUS_FAIL;
            }
        }
    }

    /*
     * We now check the results
     */
    if (CPA_STATUS_SUCCESS == status)
    {
        if (chainResult.chainStatus != CPA_DC_OK)
        {
            PRINT_ERR(
                "Results chainStatus not as expected (chainStatus = %d)\n",
                chainResult.chainStatus);
            status = CPA_STATUS_FAIL;
        }
        else if (chainResult.chainRqResults.dcStatus != CPA_DC_OK)
        {
            PRINT_ERR("Results dcStatus not as expected (dcStatus = %d)\n",
                      chainResult.chainRqResults.dcStatus);
            status = CPA_STATUS_FAIL;
        }
        else if (chainResult.chainRqResults.cyStatus != CPA_DC_OK)
        {
            PRINT_ERR("Results cyStatus not as expected (cyStatus = %d)\n",
                      chainResult.chainRqResults.cyStatus);
            status = CPA_STATUS_FAIL;
        }
        else
        {
            PRINT_DBG("Data consumed %d\n",
                      chainResult.chainRqResults.consumed);
            PRINT_DBG("Data produced %d\n",
                      chainResult.chainRqResults.produced);
            PRINT_DBG("Adler32 checksum 0x%x\n",
                      chainResult.chainRqResults.adler32);
            PRINT_DBG("Crc32 checksum 0x%x\n",
                      chainResult.chainRqResults.crc32);

            PRINT_DBG("pCrcDataBuffer->crc32 0x%x\n", pCrcDataBuffer->crc32);
            PRINT_DBG("pCrcDataBuffer->adler32 0x%x\n",
                      pCrcDataBuffer->adler32);
            PRINT_DBG("pCrcDataBuffer->integrityCrc64b.iCrc 0x%lx\n",
                      pCrcDataBuffer->integrityCrc64b.iCrc);
            PRINT_DBG("pCrcDataBuffer->integrityCrc64b.oCrc 0x%lx\n",
                      pCrcDataBuffer->integrityCrc64b.oCrc);

            PRINT_DBG("chainResult.storedCrc64 0x%lx\n",
                      chainResult.storedCrc64);
            PRINT_DBG("chainResult.iDcCrc64 0x%lx\n", chainResult.iDcCrc64);
            PRINT_DBG("chainResult.oDcCrc64 0x%lx\n", chainResult.oDcCrc64);
            PRINT_DBG("chainResult.ctxCrc64 0x%lx\n", chainResult.ctxCrc64);
        }
    }

    /* Use zlib to decompress and verify integrity */
    //<snippet name="software decompress">
    if (CPA_STATUS_SUCCESS == status)
    {
        Cpa32U srcBufferLength = 0;
        Cpa32U dstBufferLength = 0;

        /* Allow for CRC64 if appended to the compressed data */
        if (dcOpData2.appendCRC64)
        {
            appendedCrc = CPA_TRUE;
            dstBufferLength = chainResult.chainRqResults.produced +
                              DC_APPEND_CRC_SIZE_IN_BYTES;
        }
        else
        {
            dstBufferLength = chainResult.chainRqResults.produced;
        }

        copyMultiFlatBufferToBuffer(pBufferListDst, pDstBuffer);

        /* Verify Key Context if provided */
        if ((NULL != cySymOpData2.deriveCtxData.pContext) &&
            (0 != cySymOpData2.deriveCtxData.contextLen))
        {
            verifyKeyContext = CPA_TRUE;
        }

        if (CPA_DC_CHAIN_COMPRESS_THEN_AEAD == operation)
        {
            srcBufferLength = pBufferListSrc->numBuffers *
                              pBufferListSrc->pBuffers->dataLenInBytes;
            cipherSizeInBytes = dstBufferLength;
            status = dcChainingVerify(pDstBuffer,
                                      dstBufferLength,
                                      pSrcBuffer,
                                      srcBufferLength,
                                      appendedCrc,
                                      verifyKeyContext,
                                      &chainResult,
                                      &dcChainOpData2,
                                      pCrcDataBuffer);
        }
        else if (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS == operation)
        {
            status = dcChainingVerify(pDstBuffer,
                                      dstBufferLength,
                                      samplePayload,
                                      sizeof(samplePayload),
                                      appendedCrc,
                                      verifyKeyContext,
                                      &chainResult,
                                      &dcChainOpData2,
                                      pCrcDataBuffer);
        }
    }
    //</snippet>

    /*
     * At this stage, the callback function has returned, so it is
     * sure that the structures won't be needed any more.  Free the
     * memory!
     */
    PHYS_CONTIG_FREE(pAadBuffer);
    PHYS_CONTIG_FREE(pContextBuffer);
    if (!useXstorExtensions)
    {
        PHYS_CONTIG_FREE(pIvBuffer);
    }
    PHYS_CONTIG_FREE(pCrcDataBuffer);
    COMPLETION_DESTROY(&complete);
    dcChainFreeBufferList(&pBufferListSrc);
    dcChainFreeBufferList(&pBufferListDst);
    dcChainFreeBufferList(&pBufferListIntermediate);
    return status;
}

/*
 * This is the main entry point for the sample data dc chain code.
 * demonstrates the sequence of calls to be made to the API in order
 * to create a session, perform one or more hash plus compression operations,
 * and
 * then tear down the session.
 */
CpaStatus dcChainXstorSample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaInstanceHandle dcInstHandle = NULL;
    CpaDcSessionHandle sessionHdl = NULL;
    CpaDcChainSessionSetupData chainSessionData[2] = { { 0 }, { 0 } };
    CpaDcSessionSetupData dcSessionData = { 0 };
    CpaCySymSessionSetupData cySessionData = { 0 };
    Cpa32U sess_size = 0;
    CpaDcStats dcStats = { 0 };
    CpaDcInstanceCapabilities cap = { 0 };
    Cpa32U buffMetaSize = 0;
    Cpa16U numInterBuffLists = 0;
    CpaBufferList **bufferInterArray = NULL;
    Cpa16U bufferNum = 0;
    CpaStatus chainOperation = CPA_STATUS_FAIL;
    void *pSrcBuffer = samplePayload;
    Cpa32U srcBufferSize = sizeof(samplePayload);
    void *pCompEncryptBuffer = NULL;
    Cpa32U compEncryptBufferSize = 0;
    void *pDecryptDecompBuffer = NULL;
    Cpa32U decryptDecompBufferSize = 0;
    cipherSizeInBytes = 0;
    Cpa8U *pDigestBuffer = NULL;

    /*
     * In this simplified version of instance discovery, we discover
     * exactly one instance of a data compression service.
     */
    sampleDcGetInstance(&dcInstHandle);
    if (dcInstHandle == NULL)
    {
        PRINT_ERR("Get instance failed\n");
        return CPA_STATUS_FAIL;
    }

    /* Query Capabilities */
    PRINT_DBG("cpaDcQueryCapabilities\n");
    //<snippet name="queryStart">
    status = cpaDcQueryCapabilities(dcInstHandle, &cap);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Query capabilities failed\n");
        return status;
    }

    if (CPA_FALSE == CPA_BITMAP_BIT_TEST(cap.dcChainCapInfo,
                                         CPA_DC_CHAIN_COMPRESS_THEN_AEAD))
    {
        PRINT_ERR("Compress then Encrypt(AEAD) chained operation is not "
                  "supported on logical "
                  "instance: 0x%8x.\n",
                  cap.dcChainCapInfo[0]);
        return CPA_STATUS_UNSUPPORTED;
    }

    if (CPA_FALSE == CPA_BITMAP_BIT_TEST(cap.dcChainCapInfo,
                                         CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS))
    {
        PRINT_ERR("Decrypt(AEAD) then Decompress chained operation is not "
                  "supported on logical "
                  "instance: 0x%8x.\n",
                  cap.dcChainCapInfo[0]);
        return CPA_STATUS_UNSUPPORTED;
    }

    if (!cap.statelessDeflateCompression || !cap.dynamicHuffman)
    {
        PRINT_ERR("Error: Unsupported functionality\n");
        return CPA_STATUS_FAIL;
    }

    /* Note : for QAT2.x, The below block won't get executed.
     * For QAT2.x, intermediate buffers are not required,
     * Hence cpaDcGetNumIntermediateBuffers() will return 0 */
    if (cap.dynamicHuffmanBufferReq)
    {
        status = cpaDcBufferListGetMetaSize(dcInstHandle, 1, &buffMetaSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            status = cpaDcGetNumIntermediateBuffers(dcInstHandle,
                                                    &numInterBuffLists);
        }
        if (CPA_STATUS_SUCCESS == status && 0 != numInterBuffLists)
        {
            status = PHYS_CONTIG_ALLOC(
                &bufferInterArray, numInterBuffLists * sizeof(CpaBufferList *));
        }
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum],
                                           sizeof(CpaBufferList));
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                status = PHYS_CONTIG_ALLOC(
                    &bufferInterArray[bufferNum]->pPrivateMetaData,
                    buffMetaSize);
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                status =
                    PHYS_CONTIG_ALLOC(&bufferInterArray[bufferNum]->pBuffers,
                                      sizeof(CpaFlatBuffer));
            }
            if (CPA_STATUS_SUCCESS == status)
            {
                /* Implementation requires an intermediate buffer approximately
                           twice the size of the output buffer */
                status = PHYS_CONTIG_ALLOC(
                    &bufferInterArray[bufferNum]->pBuffers->pData,
                    2 * SAMPLE_MAX_BUFF);
                bufferInterArray[bufferNum]->numBuffers = 1;
                bufferInterArray[bufferNum]->pBuffers->dataLenInBytes =
                    2 * SAMPLE_MAX_BUFF;
            }

        } /* End numInterBuffLists */
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set the address translation function for the instance */
        status = cpaDcSetAddressTranslation(dcInstHandle, sampleVirtToPhys);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Start static data compression component */
        PRINT_DBG("cpaDcStartInstance\n");
        status = cpaDcStartInstance(
            dcInstHandle, numInterBuffLists, bufferInterArray);
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * If the instance is polled start the polling thread. Note that
         * how the polling is done is implementation-dependent.
         */
        sampleDcStartPolling(dcInstHandle);
        /*
         * We now populate the fields of the session operational data and create
         * the session.  Note that the size required to store a session is
         * implementation-dependent, so we query the API first to determine how
         * much memory to allocate, and then allocate that memory.
         */
        PRINT_DBG("DC Chain Operation: Compress(DEFLATE) then Encrypt (AES256 "
                  "GCM)\n");

        //<snippet name="initSession">
        /* Initialize compression session data */
        dcSessionData.compLevel = CPA_DC_L1;
        dcSessionData.compType = CPA_DC_DEFLATE;
        dcSessionData.huffType = CPA_DC_HT_FULL_DYNAMIC;
        dcSessionData.autoSelectBestHuffmanTree = CPA_DC_ASB_DISABLED;
        dcSessionData.sessDirection = CPA_DC_DIR_COMPRESS;
        dcSessionData.sessState = CPA_DC_STATELESS;
        dcSessionData.checksum = CPA_DC_CRC32;

        /* Initialize crypto session data */
        cySessionData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        cySessionData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        cySessionData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
        cySessionData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_GCM;
        if (useXstorExtensions)
        {
            cySessionData.cipherSetupData.pCipherKey = NULL;
            cySessionData.cipherSetupData.cipherKeyLenInBytes = 0;
        }
        else
        {
            cySessionData.cipherSetupData.pCipherKey = ctxSampleKey;
            cySessionData.cipherSetupData.cipherKeyLenInBytes =
                sizeof(ctxSampleKey);
        }
        cySessionData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;

        cySessionData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_GCM;
        cySessionData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        cySessionData.hashSetupData.digestResultLenInBytes = TAG_LENGTH;
        /* For GCM authKey and authKeyLen are not required this information
           is provided by the cipherKey in cipherSetupData */
        cySessionData.hashSetupData.authModeSetupData.aadLenInBytes =
            sizeof(sampleAddAuthData);
        cySessionData.digestIsAppended = CPA_FALSE;
        /* digestVerify is not required to be set. For GCM authenticated
           encryption this value is understood to be CPA_FALSE */

        /* Initialize chaining session data - compress + encrypt
         * chain operation */
        chainSessionData[0].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
        chainSessionData[0].pDcSetupData = &dcSessionData;
        chainSessionData[1].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
        chainSessionData[1].pCySetupData = &cySessionData;

        /* Determine size of session context to allocate */
        PRINT_DBG("cpaDcChainGetSessionSize\n");
        status = cpaDcChainGetSessionSize(dcInstHandle,
                                          CPA_DC_CHAIN_COMPRESS_THEN_AEAD,
                                          NUM_SESSIONS_TWO,
                                          chainSessionData,
                                          &sess_size);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Allocate session memory */
        status = PHYS_CONTIG_ALLOC(&sessionHdl, sess_size);
    }

    /* Initialize the chaining session */
    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("cpaDcChainInitSession\n");
        status = cpaDcChainInitSession(dcInstHandle,
                                       sessionHdl,
                                       CPA_DC_CHAIN_COMPRESS_THEN_AEAD,
                                       NUM_SESSIONS_TWO,
                                       chainSessionData,
                                       dcCallback);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the CRC parameters if using programmable CRC feature */
        if (!useHardCodedCrc)
        {
            status = cpaDcChainSetCrcControlData(
                dcInstHandle, sessionHdl, &progCrcControlData);
        }
    }
    //</snippet>

    if (CPA_STATUS_SUCCESS == status)
    {
        compEncryptBufferSize = (4 * srcBufferSize);
        status = PHYS_CONTIG_ALLOC(&pCompEncryptBuffer, compEncryptBufferSize);

        /* Allocate digest result buffer */
        if (CPA_STATUS_SUCCESS == status)
        {
            status = PHYS_CONTIG_ALLOC(&pDigestBuffer, TAG_LENGTH);
        }

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Perform chaining operation */
            chainOperation =
                dcChainingPerformOp(dcInstHandle,
                                    sessionHdl,
                                    CPA_DC_CHAIN_COMPRESS_THEN_AEAD,
                                    pSrcBuffer,
                                    srcBufferSize,
                                    pCompEncryptBuffer,
                                    compEncryptBufferSize,
                                    compEncryptBufferSize,
                                    pDigestBuffer,
                                    CPA_FALSE);
        }

        if (CPA_STATUS_SUCCESS != chainOperation)
        {
            PRINT_ERR("dcChainingPerformOp (CPA_DC_CHAIN_COMPRESS_THEN_AEAD) "
                      "failed\n");
        }
        /*
         * In a typical usage, the session might be used to compression
         * multiple buffers.  In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("cpaDcChainRemoveSession\n");
        //<snippet name="removeSession">
        status = cpaDcChainRemoveSession(dcInstHandle, sessionHdl);
        //</snippet>

        if (CPA_STATUS_SUCCESS != chainOperation)
        {
            status = chainOperation;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("DC Chain Operation: Decrypt (AES256 GCM) then "
                  "Decompress(DEFLATE decompress)\n");

        /* Initialize compression session data */
        dcSessionData.compType = CPA_DC_DEFLATE;
        dcSessionData.sessDirection = CPA_DC_DIR_DECOMPRESS;
        dcSessionData.sessState = CPA_DC_STATELESS;
        dcSessionData.checksum = CPA_DC_CRC32;

        /* Initialize crypto session data */
        cySessionData.sessionPriority = CPA_CY_PRIORITY_NORMAL;
        cySessionData.symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;
        cySessionData.algChainOrder =
            CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
        cySessionData.cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_GCM;
        if (useXstorExtensions)
        {
            cySessionData.cipherSetupData.pCipherKey = NULL;
            cySessionData.cipherSetupData.cipherKeyLenInBytes = 0;
        }
        else
        {
            cySessionData.cipherSetupData.pCipherKey = ctxSampleKey;
            cySessionData.cipherSetupData.cipherKeyLenInBytes =
                sizeof(ctxSampleKey);
        }
        cySessionData.cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;

        cySessionData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_AES_GCM;
        cySessionData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
        cySessionData.hashSetupData.digestResultLenInBytes = TAG_LENGTH;
        /* For GCM authKey and authKeyLen are not required this information
           is provided by the cipherKey in cipherSetupData */
        cySessionData.hashSetupData.authModeSetupData.aadLenInBytes =
            sizeof(sampleAddAuthData);
        cySessionData.digestIsAppended = CPA_FALSE;
        /* digestVerify is not required to be set. For GCM authenticated
           encryption this value is understood to be CPA_FALSE */

        /* Initialize chaining session data - decrypt + decompress
         * chain operation */
        chainSessionData[0].sessType = CPA_DC_CHAIN_SYMMETRIC_CRYPTO;
        chainSessionData[0].pCySetupData = &cySessionData;
        chainSessionData[1].sessType = CPA_DC_CHAIN_COMPRESS_DECOMPRESS;
        chainSessionData[1].pDcSetupData = &dcSessionData;

        /* Initialize the chaining session */
        if (CPA_STATUS_SUCCESS == status)
        {
            PRINT_DBG("cpaDcChainInitSession\n");
            status = cpaDcChainInitSession(dcInstHandle,
                                           sessionHdl,
                                           CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS,
                                           NUM_SESSIONS_TWO,
                                           chainSessionData,
                                           dcCallback);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Initialize the CRC parameters if using programmable CRC feature */
        if (!useHardCodedCrc)
        {
            status = cpaDcChainSetCrcControlData(
                dcInstHandle, sessionHdl, &progCrcControlData);
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        decryptDecompBufferSize = (4 * srcBufferSize);
        status =
            PHYS_CONTIG_ALLOC(&pDecryptDecompBuffer, decryptDecompBufferSize);

        if (CPA_STATUS_SUCCESS == status)
        {
            /* Perform chaining operation */
            chainOperation =
                dcChainingPerformOp(dcInstHandle,
                                    sessionHdl,
                                    CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS,
                                    pCompEncryptBuffer,
                                    compEncryptBufferSize,
                                    pDecryptDecompBuffer,
                                    decryptDecompBufferSize,
                                    compEncryptBufferSize,
                                    pDigestBuffer,
                                    CPA_FALSE);
        }

        if (CPA_STATUS_SUCCESS != chainOperation)
        {
            PRINT_ERR("dcChainingPerformOp (CPA_DC_CHAIN_AEAD_THEN_DECOMPRESS) "
                      "failed\n");
        }
        /*
         * In a typical usage, the session might be used to compression
         * multiple buffers.  In this example however, we can now
         * tear down the session.
         */
        PRINT_DBG("cpaDcChainRemoveSession\n");
        //<snippet name="removeSession">
        status = cpaDcChainRemoveSession(dcInstHandle, sessionHdl);
        //</snippet>

        if (CPA_STATUS_SUCCESS != chainOperation)
        {
            status = chainOperation;
        }
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        /*
         * We can now query the statistics on the instance.
         *
         * Note that some implementations may also make the stats
         * available through other mechanisms, e.g. in the /proc
         * virtual filesystem.
         */
        status = cpaDcGetStats(dcInstHandle, &dcStats);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("cpaDcGetStats failed, status = %d\n", status);
        }
        else
        {
            PRINT_DBG("Number of compression operations completed: %llu\n",
                      (unsigned long long)dcStats.numCompCompleted);
        }
    }

    /*
     * Free up memory, stop the instance, etc.
     */

    /* Stop the polling thread */
    sampleDcStopPolling();

    PRINT_DBG("cpaDcStopInstance\n");
    cpaDcStopInstance(dcInstHandle);

    /* Free output buffers used */
    PHYS_CONTIG_FREE(pCompEncryptBuffer);
    PHYS_CONTIG_FREE(pDigestBuffer);
    PHYS_CONTIG_FREE(pDecryptDecompBuffer);

    /* Free session Context */
    PHYS_CONTIG_FREE(sessionHdl);

    /* Free intermediate buffers */
    if (bufferInterArray != NULL)
    {
        for (bufferNum = 0; bufferNum < numInterBuffLists; bufferNum++)
        {
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers->pData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pBuffers);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]->pPrivateMetaData);
            PHYS_CONTIG_FREE(bufferInterArray[bufferNum]);
        }
        PHYS_CONTIG_FREE(bufferInterArray);
    }

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Sample code ran successfully\n");
    }
    else
    {
        PRINT_ERR("Sample code failed with status of %d\n", status);
    }

    return status;
}
