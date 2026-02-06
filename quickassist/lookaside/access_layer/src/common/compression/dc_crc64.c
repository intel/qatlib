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
 * @file dc_crc64.c
 *
 * @defgroup Dc_DataCompression DC Data Compression
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Implementation of the CRC-64 operations.
 *
 *****************************************************************************/

#include "dc_crc64.h"

/* Number of bits in a byte */
#define NUM_BITS_PER_BYTE 8

/* Number of bits in a 64bit parameter */
#define NUM_BITS_PER_64BIT 64

/* Mask for a byte */
#define BYTE_MASK 0xFF

/* Mask for the most significant bit in a 8bit parameter */
#define MOST_SIGNIFICANT_8BIT_MASK 0x80

/* Mask for the most significant bit in a 64bit parameter */
#define MOST_SIGNIFICANT_64BIT_MASK 0x8000000000000000ULL

/* Bit index (zero based) of the most significant byte in a 64bit parameter */
#define MOST_SIGNIFICANT_BYTE_BIT_INDEX 56

/* Maximum number of possible byte values */
#define MAX_NUM_BYTE_VALUES 256

/* CRC lookup table is 256 * 64bit entries */
#define CRC_LOOKUP_TABLE_SIZE_IN_BYTES MAX_NUM_BYTE_VALUES * sizeof(Cpa64U)

/**
 * @description
 *     Calculates CRC-64 checksum for given Buffer List
 *
 *     Function loop through all of the flat buffers in the buffer list.
 *     CRC is calculated for each flat buffer, but output CRC from
 *     buffer[0] is used as input seed for buffer[1] CRC calculation
 *     (and so on until looped through all flat buffers).
 *     Resulting CRC is final CRC for all buffers in the buffer list struct
 *
 * @param[in]  bufferList      Pointer to data byte array to calculate CRC on
 * @param[in]  consumedBytes   Total number of bytes to calculate CRC on
 *                             (for all buffer in buffer list)
 * @param[in]  seedChecksums   Input checksum from where the calculation will
 *                             start from.
 *
 * @retval Cpa64U              64bit long CRC checksum for given buffer list
 */
Cpa64U dcCalculateCrc64(const CpaBufferList *pBufferList,
                        Cpa32U consumedBytes,
                        Cpa64U seedChecksum)
{
    Cpa32U i = 0;
    Cpa64U computeLength = 0;
    Cpa32U flatBufferLength = 0;
    Cpa64U currentCrc = seedChecksum;
    CpaFlatBuffer *pBuffer = &pBufferList->pBuffers[0];

    for (i = 0; i < pBufferList->numBuffers; i++)
    {
        flatBufferLength = pBuffer->dataLenInBytes;

        /* Get number of bytes based on remaining data (consumedBytes) and
         * max buffer length, then calculate CRC on them */
        if (consumedBytes > flatBufferLength)
        {
            computeLength = flatBufferLength;
            consumedBytes -= flatBufferLength;
        }
        else
        {
            computeLength = consumedBytes;
            consumedBytes = 0;
        }
#ifdef USE_CCODE_CRC
        currentCrc =
            crc64_ecma_norm_base(currentCrc, pBuffer->pData, computeLength);
#else
        currentCrc =
            crc64_ecma_norm_by8(currentCrc, pBuffer->pData, computeLength);
#endif
        pBuffer++;
    }

    return currentCrc;
}

/**
 * @description
 *     Reflects the 8bit input parameter.
 *
 *     CRC support function to reflect the 8bit input parameter.
 *
 *     Example - 8bit input parameter: 0xBE
 *     (10111110)
 *     Becomes:
 *     8bit reflected parameter: 0x7D
 *     (01111101)
 *
 * @param[in]  value       8bit input parameter to reflect.
 * @param[out] reflectVal  8bit reflected output.
 */
STATIC Cpa8U dcSwReflect8(Cpa8U value)
{
    Cpa8U inputVal = value;
    Cpa8U reflectVal = 0;
    Cpa32U i = 0;

    for (i = 0; i < NUM_BITS_PER_BYTE; i++)
    {
        reflectVal = (reflectVal << 1) | (inputVal & 1);
        inputVal >>= 1;
    }
    return reflectVal;
}

/**
 * @description
 *     Reflects the 64bit input parameter.
 *
 *     CRC support function to reflect the 64bit input parameter.
 *
 *     Example - 64bit input parameter: 0xBBE4A6466F216080
 *     (1011101111100100101001100100011001101111001000010110000010000000)
 *     Becomes:
 *     64bit reflected parameter: 0x010684F6626527DD
 *     (0000000100000110100001001111011001100010011001010010011111011101)
 *
 * @param[in]  value       64bit input parameter to reflect.
 * @param[out] reflectVal  64bit reflected output.
 */
STATIC Cpa64U dcSwReflect64(Cpa64U value)
{
    Cpa32U i = 0;
    Cpa64U inputVal = value;
    Cpa64U reflectVal = 0;

    for (i = 0; i < NUM_BITS_PER_64BIT; i++)
    {
        reflectVal = (reflectVal << 1) | (inputVal & 1);
        inputVal >>= 1;
    }
    return reflectVal;
}

/**
 * @description
 *     Creates a lookup table for CRC64 calculation
 *
 *     Function creates a lookup table for a given polynomial. This table is
 *     used to speed up CRC64 calculation at runtime.
 *
 * @param[in]  crc64Polynomial  CRC64 polynomial used for generating the CRC
 *                              lookup table.
 * @param[out] ppCrcLookupTable  Address of pointer to the CRC lookup table
 *                              created.
 *
 * @retval CPA_STATUS_SUCCESS   Function executed successfully
 * @retval CPA_STATUS_RESOURCE  Memory allocation error
 *
 */
CpaStatus dcGenerateLookupTable(Cpa64U crc64Polynomial,
                                Cpa64U **ppCrcLookupTable)
{

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(ppCrcLookupTable);
#endif

    Cpa32U j = 0;
    Cpa64U i = 0;
    Cpa64U tableEntry = 0;

    /* Allocate the CRC64 lookup table */
    *ppCrcLookupTable = NULL;
    if (CPA_STATUS_SUCCESS !=
        LAC_OS_MALLOC(ppCrcLookupTable, CRC_LOOKUP_TABLE_SIZE_IN_BYTES))
    {
        LAC_LOG_ERROR("Unable to allocate memory for CRC lookup table");
        return CPA_STATUS_RESOURCE;
    }

    /* Loop through all possible byte values */
    for (i = 0; i < MAX_NUM_BYTE_VALUES; i++)
    {
        /* Move to most significant byte of 64bit */
        tableEntry = (i << MOST_SIGNIFICANT_BYTE_BIT_INDEX);

        /* For each bit in the byte */
        for (j = 0; j < NUM_BITS_PER_BYTE; j++)
        {
            /* Check if the most significant bit is set */
            if (tableEntry & MOST_SIGNIFICANT_64BIT_MASK)
            {
                /* XOR with polynomial if set */
                tableEntry = (tableEntry << 1) ^ crc64Polynomial;
            }
            else
            {
                tableEntry = tableEntry << 1;
            }
        }

        /* Store result in the lookup table */
        (*ppCrcLookupTable)[i] = tableEntry;
    }
    return CPA_STATUS_SUCCESS;
}

/**
 * @description
 *     Calculates CRC-64 checksum for the given flat buffer length
 *
 *     Function calculates the 64bit CRC on the given flat buffer for the
 *     requested length.
 *
 * @param[in]  pCrcConfig           Pointer to the CRC configuration used for
 *                                  calculating the checksum.
 * @param[in]  pCrcLookupTable      Pointer to the CRC lookup table used for
 *                                  calculating the checksum.
 * @param[in]  pData                Pointer to data byte array to calculate CRC
 *                                  on.
 * @param[in]  computeLength        Total number of bytes to calculate CRC on.
 * @param[out] pCurrentCrc          Pointer to 64bit long CRC checksum for the
 *                                  given flat buffer length.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in
 */
STATIC CpaStatus dcBufferCalculateCrc64(const CpaCrcControlData *pCrcConfig,
                                        const Cpa64U *pCrcLookupTable,
                                        const Cpa8U *pData,
                                        Cpa64U computeLength,
                                        Cpa64U *pCurrentCrc)
{
    Cpa8U nextByte = 0;
    Cpa8U position = 0;
    Cpa64U i = 0;

#ifdef ICP_PARAM_CHECK
    LAC_CHECK_NULL_PARAM(pCrcConfig);
    LAC_CHECK_NULL_PARAM(pData);
    LAC_CHECK_NULL_PARAM(pCurrentCrc);
    LAC_CHECK_NULL_PARAM(pCrcLookupTable);
#endif

    *pCurrentCrc = pCrcConfig->initialValue;
    for (i = 0; i < computeLength; i++)
    {
        nextByte = pData[i];
        if (pCrcConfig->reflectIn)
        {
            /* Get the byte reflected value */
            nextByte = dcSwReflect8(nextByte);
        }

        /* Calculate the position in the lookup table */
        position =
            ((*pCurrentCrc >> MOST_SIGNIFICANT_BYTE_BIT_INDEX) ^ nextByte) &
            BYTE_MASK;

        /* Generate the CRC using the lookup table position */
        *pCurrentCrc =
            (*pCurrentCrc << NUM_BITS_PER_BYTE) ^ pCrcLookupTable[position];
    }
    return CPA_STATUS_SUCCESS;
}

/**
 * @description
 *     Calculates programmable CRC-64 checksum for given Buffer List
 *
 *     Function loops through all of the flat buffers in the buffer list.
 *     CRC is calculated for each flat buffer, but output CRC from
 *     buffer[0] is used as input seed for buffer[1] CRC calculation
 *     (and so on until looped through all flat buffers).
 *     Resulting CRC is final CRC for all buffers in the buffer list struct
 *
 * @param[in]  pCrcConfig           Pointer to the CRC configuration used for
 *                                  calculating the checksum.
 * @param[in]  pCrcLookupTable      Pointer to the CRC lookup table used for
 *                                  calculating the checksum.
 * @param[in]  bufferList           Pointer to data byte array to calculate CRC
 *                                  on.
 * @param[in]  consumedBytes        Total number of bytes to calculate CRC on
 *                                  (for all buffers in buffer list)
 * @param[out] pSwCrc               Pointer to 64bit long CRC checksum for the
 *                                  given buffer list.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully
 * @retval CPA_STATUS_INVALID_PARAM Invalid parameter passed in
 */
CpaStatus dcCalculateProgCrc64(CpaCrcControlData *pCrcConfig,
                               Cpa64U *pCrcLookupTable,
                               const CpaBufferList *pBufferList,
                               Cpa32U consumedBytes,
                               Cpa64U *pSwCrc)
{
    Cpa64U i = 0;
    Cpa64U computeLength = 0;
    Cpa32U flatBufferLength = 0;
    CpaFlatBuffer *pBuffer = &pBufferList->pBuffers[0];
    CpaStatus status = CPA_STATUS_SUCCESS;

    for (i = 0; i < pBufferList->numBuffers; i++)
    {
        flatBufferLength = pBuffer->dataLenInBytes;

        /* Get number of bytes based on remaining data (consumedBytes) and
         * max buffer length, then calculate CRC on them */
        if (consumedBytes > flatBufferLength)
        {
            computeLength = flatBufferLength;
            consumedBytes -= flatBufferLength;
        }
        else
        {
            computeLength = consumedBytes;
            consumedBytes = 0;
        }

        status = dcBufferCalculateCrc64(
            pCrcConfig, pCrcLookupTable, pBuffer->pData, computeLength, pSwCrc);
        if (CPA_STATUS_SUCCESS != status)
        {
            return status;
        }
        pCrcConfig->initialValue = *pSwCrc;
        pBuffer++;
    }

    if (pCrcConfig->reflectOut)
    {
        /* Reflect the 64bit CRC */
        *pSwCrc = dcSwReflect64(*pSwCrc);
    }

    *pSwCrc = *pSwCrc ^ pCrcConfig->xorOut;
    return status;
}
