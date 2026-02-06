/***************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 * This file contains the KDF (key derivation function) and HASH (SM3) utilities
 * to build up the SM2 sample code.
 *
 * More details about the KDF function see
 *     http://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 *
 * More details about the SM3 hash function see
 *     http://tools.ietf.org/html/draft-shen-sm3-hash-00
 *
 * To complete a full process of the SM2 encryption, decryption, key exchange,
 * etc, the KDF & SM3 HASH computation are required, this file is just used by
 * the SM2 sample code to demonstrate how to build up the full SM2 algorithm
 * flows.
 *
 *
 ***************************************************************************/
#include <linux/string.h>
#include "cpa.h"
#include "cpa_types.h"
/**
 ******************************************************************************
 * Standard operations according to the Spec.
 ******************************************************************************/
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

#define SHL(x, n) (((x)&0xFFFFFFFF) << n)
#define ROTL(x, n) (SHL((x), n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

#define SM3_HASH_SIZE_IN_BYTE (32)
/**
 ******************************************************************************
 * Convert 4 bytes to unsigned long
 * Big endian according to the Spec.
 ******************************************************************************/
#define BYTES_TO_ULONG(l, b, i)                                                \
    {                                                                          \
        (l) = ((Cpa32U)(b)[(i)] << 24) | ((Cpa32U)(b)[(i) + 1] << 16) |        \
              ((Cpa32U)(b)[(i) + 2] << 8) | ((Cpa32U)(b)[(i) + 3]);            \
    }
/**
 ******************************************************************************
 * Convert unsigned long to 4 bytes
 * Big endian according to the Spec.
 ******************************************************************************/
#define ULONG_TO_BYTES(l, b, i)                                                \
    {                                                                          \
        (b)[(i)] = (Cpa8U)((l) >> 24);                                         \
        (b)[(i) + 1] = (Cpa8U)((l) >> 16);                                     \
        (b)[(i) + 2] = (Cpa8U)((l) >> 8);                                      \
        (b)[(i) + 3] = (Cpa8U)((l));                                           \
    }

/* constant data define */
#define BLOCK_BYTE_LEN 64
#define MSG_BYTE_LEN 8
#define W_BYTE_LEN 68
#define W1_BYTE_LEN 64
#define T_BYTE_LEN 64

/**
 ******************************************************************************
 * Assume a message has length l.  First add the bit "1" to the end of
 * this message, then add k bits of "0", such that k is the smallest
 * non-negative integer satisfyingGBPo
 *
 *  l+1+k = 448 mod 512
 *
 * Then add a 64 bits string, which is the binary expression of length l.
 * After padding, the length of the new message m' is a multiple of 512.
 * Here defines a 64 bytes array, according to the numbers need to be filled
 * Pad the bytes to the end of the data.
 ******************************************************************************/
static const Cpa8U sm3PaddingData[BLOCK_BYTE_LEN] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/**
 ******************************************************************************
 * SM3 block data process function
 * Each block 512bits(64 byte)
 ******************************************************************************/
static void sm3BlockProcess(Cpa32U *sm3_state, Cpa8U *sm3_buffer)
{
    Cpa32U SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0, W[W_BYTE_LEN] = {0},
           W1[W1_BYTE_LEN] = {0};
    Cpa32U A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0;
    Cpa64U T[T_BYTE_LEN] = { 0 };
    Cpa32U Temp1 = 0, Temp2 = 0, Temp3 = 0, Temp4 = 0, Temp5 = 0;
    Cpa32S j = 0;
    /* according to the spec, the block processing is divided into
     * two parts, index from 0 ~ 15 and 16 ~ 63, using different
     * constants 0x79CC4519, 0x7A879D8A */
    for (j = 0; j < 16; j++)
        /*constant number defined in the spec*/
        T[j] = 0x79CC4519;
    for (j = 16; j < 64; j++)
        /*constant number defined in the spec*/
        T[j] = 0x7A879D8A;
    /*convert the buffer data to word (big endian) */
    BYTES_TO_ULONG(W[0], sm3_buffer, 0);
    BYTES_TO_ULONG(W[1], sm3_buffer, 4);
    BYTES_TO_ULONG(W[2], sm3_buffer, 8);
    BYTES_TO_ULONG(W[3], sm3_buffer, 12);
    BYTES_TO_ULONG(W[4], sm3_buffer, 16);
    BYTES_TO_ULONG(W[5], sm3_buffer, 20);
    BYTES_TO_ULONG(W[6], sm3_buffer, 24);
    BYTES_TO_ULONG(W[7], sm3_buffer, 28);
    BYTES_TO_ULONG(W[8], sm3_buffer, 32);
    BYTES_TO_ULONG(W[9], sm3_buffer, 36);
    BYTES_TO_ULONG(W[10], sm3_buffer, 40);
    BYTES_TO_ULONG(W[11], sm3_buffer, 44);
    BYTES_TO_ULONG(W[12], sm3_buffer, 48);
    BYTES_TO_ULONG(W[13], sm3_buffer, 52);
    BYTES_TO_ULONG(W[14], sm3_buffer, 56);
    BYTES_TO_ULONG(W[15], sm3_buffer, 60);

    for (j = 16; j < W_BYTE_LEN; j++)
    {
        Temp1 = W[j - 16] ^ W[j - 9];
        Temp2 = ROTL(W[j - 3], 15);
        Temp3 = Temp1 ^ Temp2;
        Temp4 = P1(Temp3);
        Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
        W[j] = Temp4 ^ Temp5;
    }

    for (j = 0; j < W1_BYTE_LEN; j++)
    {
        W1[j] = W[j] ^ W[j + 4];
    }

    A = sm3_state[0];
    B = sm3_state[1];
    C = sm3_state[2];
    D = sm3_state[3];
    E = sm3_state[4];
    F = sm3_state[5];
    G = sm3_state[6];
    H = sm3_state[7];
    /* according to the spec, the block processing is divided into
     * two parts, index from 0 ~ 15 and 16 ~ 63, using different
     * constants T[i] (0x79CC4519, 0x7A879D8A) and different MACRO
     * FF0/GG0 and FF1/GG1
     */
    for (j = 0; j < 16; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    for (j = 16; j < 64; j++)
    {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }

    sm3_state[0] ^= A;
    sm3_state[1] ^= B;
    sm3_state[2] ^= C;
    sm3_state[3] ^= D;
    sm3_state[4] ^= E;
    sm3_state[5] ^= F;
    sm3_state[6] ^= G;
    sm3_state[7] ^= H;
}

/**
 ******************************************************************************
 * SM3 process function
 * Padding input data according to ilen
 * Call sm3BlockProcess for each data block
 * param: input data; input data length; state register ptr; state buffer ptr
 *        filled; message length buffer
 ******************************************************************************/
static void sm3Process(Cpa8U *input,
                       Cpa64U ilen,
                       Cpa32U *sm3_state,
                       Cpa8U *sm3_buffer,
                       Cpa32U *pfilled,
                       Cpa8U *message_len)
{
    /* If input length is larger than 64 bytes, process each 64-byte block in a
     * loop */
    if (ilen >= 64)
    {
        while (ilen >= 64)
        {
            memcpy((void *)(sm3_buffer), (void *)input, BLOCK_BYTE_LEN);
            sm3BlockProcess(sm3_state, sm3_buffer);
            input += BLOCK_BYTE_LEN;
            ilen -= BLOCK_BYTE_LEN;
        }
    }
    /* Process the last block data, which is padded by (1000...message_length)
     * */
    memcpy((void *)(sm3_buffer), (void *)input, ilen);
    memcpy((void *)(sm3_buffer + ilen), (void *)sm3PaddingData, *pfilled);
    memcpy((void *)(sm3_buffer + ilen + *pfilled),
           (void *)message_len,
           MSG_BYTE_LEN);
    sm3BlockProcess(sm3_state, sm3_buffer);
}

/**
 ******************************************************************************
 * SM3 Hash function
 * param input  : input message, input message length
 * param output : digest output buffer
 ******************************************************************************/
void sm3(Cpa8U *input, Cpa64U ilen, Cpa8U *output)
{

    /* Sm3 intermediate state  */
    Cpa32U sm3_state[8] = {0};
    /* Data buffer */
    Cpa8U sm3_buffer[64] = {0};
    /* Assume a message has length l.  First add the bit "1" to the end of
     * this message, then add k bits of "0", such that k is the smallest
     * non-negative integer satisfyingGBPo
     *
     *  l+1+k = 448 mod 512
     *
     * Then add a 64 bits string, which is the binary expression of length l.
     * After padding, the length of the new message m' is a multiple of 512.
     *
     * "filled" calculate the number of bytes need to be padding at the end
     * The last block should be 64 bytes(512 bits)
     * Then filled = BLOCK_BYTE_LEN - (input length % BLOCK_BYTE_LEN) -
     * MSG_BYTE_LEN
     */
    Cpa32U filled = 0;
    /* Message length */
    Cpa8U message_len[8] = {0};

    Cpa64U ilenbits = ilen * 8;
    filled = BLOCK_BYTE_LEN - (ilen % BLOCK_BYTE_LEN) - MSG_BYTE_LEN;
    /* Initial value of the state register, this is defined in the spec*/
    sm3_state[0] = 0x7380166F;
    sm3_state[1] = 0x4914B2B9;
    sm3_state[2] = 0x172442D7;
    sm3_state[3] = 0xDA8A0600;
    sm3_state[4] = 0xA96F30BC;
    sm3_state[5] = 0x163138AA;
    sm3_state[6] = 0xE38DEE4D;
    sm3_state[7] = 0xB0FB0E4E;
    /* According to the spec, the message length need to be padding to
     * the end of the data as a bit string.
     * Convert the length value to a byte array
     */
    ULONG_TO_BYTES((Cpa32U)(ilenbits >> 32), message_len, 0);
    ULONG_TO_BYTES((Cpa32U)(ilenbits), message_len, 4);
    /* Sm3 data process function*/
    sm3Process(input, ilen, sm3_state, sm3_buffer, &filled, message_len);
    /* Copy the result in state registers to the output buffer*/
    ULONG_TO_BYTES(sm3_state[0], output, 0);
    ULONG_TO_BYTES(sm3_state[1], output, 4);
    ULONG_TO_BYTES(sm3_state[2], output, 8);
    ULONG_TO_BYTES(sm3_state[3], output, 12);
    ULONG_TO_BYTES(sm3_state[4], output, 16);
    ULONG_TO_BYTES(sm3_state[5], output, 20);
    ULONG_TO_BYTES(sm3_state[6], output, 24);
    ULONG_TO_BYTES(sm3_state[7], output, 28);
}
/**
 ******************************************************************************
 * KDF function
 * param input  : inbuf, Flatbuf of input message
 *         note : When alloc a piece of memory for the input message buffer
 *                (eg. inbuf->pData)
 *                more 4 bytes should be alloced, for an efficient padding
 *                scheme, while the ilen should be added 4 bytes on the original
 *                input message length (inbuf->dataLenInBytes).
 *
 * param output : output buffer
 ******************************************************************************/
CpaStatus kdf(CpaFlatBuffer *inbuf, CpaFlatBuffer *outbuf)
{
    Cpa32U i = 0;
    CpaStatus status = CPA_STATUS_FAIL;
    Cpa32U processed = 0;
    Cpa8U ctBytes[4] = {0};
    /* According to the spec, KDF function will pad a counter at the end of
     * each block */
    Cpa32U ct = 0x00000001;
    /* Calculate the numbers of the blocks */
    Cpa32U numOfBlocks = outbuf->dataLenInBytes / SM3_HASH_SIZE_IN_BYTE;
    /* Calculate the numbers of bytes of the last output block */
    Cpa32U finalBlockBytes = outbuf->dataLenInBytes % SM3_HASH_SIZE_IN_BYTE;
    /* Temp buffer for hash value of each block */
    Cpa8U hashBuffer[SM3_HASH_SIZE_IN_BYTE];
    for (i = 0; i < numOfBlocks; i++)
    {
        /* Convert the counter to 4 bytes*/
        ULONG_TO_BYTES(ct, ctBytes, 0);
        /* Padding 4 bytes counter for each data block */
        memcpy(inbuf->pData + inbuf->dataLenInBytes - 4, ctBytes, 4);
        /* Calculate the hash value of each data block */
        sm3(inbuf->pData, inbuf->dataLenInBytes, hashBuffer);
        /* Cat the hash value in order */
        memcpy(outbuf->pData + processed, hashBuffer, SM3_HASH_SIZE_IN_BYTE);
        ct++;
        processed += SM3_HASH_SIZE_IN_BYTE;
    }
    /* Process the last data block, according to the spec, KDF function will
     * output a variable length of message, the last data block will be
     * truncated.
     */
    ULONG_TO_BYTES(ct, ctBytes, 0);
    memcpy(inbuf->pData + inbuf->dataLenInBytes - 4, ctBytes, 4);
    sm3(inbuf->pData, inbuf->dataLenInBytes, hashBuffer);
    memcpy(outbuf->pData + processed, hashBuffer, finalBlockBytes);
    return status;
}
