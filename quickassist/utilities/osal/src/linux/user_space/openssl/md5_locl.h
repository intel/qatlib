/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file md5_locl.h
 *
 * @note
 *    This file is taken from the OpenSSL project to reuse
 *    the functionality and modified in order to prevent conflicts with
 *    public symbols in another existing OpenSSL library:
 *    - renames the public functions to have ossl_ prefix
 *    - makes non-public functions static
 *    - modifies path to the header files
 *
 * @par
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2020 Intel Corporation. All rights reserved.
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
 */

#include <stdlib.h>
#include <string.h>
#include "e_os2.h"
#include "md5.h"

#ifdef MD5_ASM
# if defined(__i386) || defined(__i386__) || defined(_M_IX86) || \
     defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#  define md5_block_data_order md5_block_asm_data_order
# elif defined(__ia64) || defined(__ia64__) || defined(_M_IA64)
#  define md5_block_data_order md5_block_asm_data_order
# elif defined(__sparc) || defined(__sparc__)
#  define md5_block_data_order md5_block_asm_data_order
# endif
#endif

void ossl_md5_block_data_order(MD5_CTX *c, const void *p, size_t num);

#define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_LONG               MD5_LONG
#define HASH_CTX                MD5_CTX
#define HASH_CBLOCK             MD5_CBLOCK
#define HASH_UPDATE             ossl_MD5_Update
#define HASH_TRANSFORM          ossl_MD5_Transform
#define HASH_FINAL              ossl_MD5_Final
#define HASH_MAKE_STRING(c,s)   do {    \
        unsigned long ll;               \
        ll=(c)->A; (void)HOST_l2c(ll,(s));      \
        ll=(c)->B; (void)HOST_l2c(ll,(s));      \
        ll=(c)->C; (void)HOST_l2c(ll,(s));      \
        ll=(c)->D; (void)HOST_l2c(ll,(s));      \
        } while (0)
#define HASH_BLOCK_DATA_ORDER   ossl_md5_block_data_order

#include "md32_common.h"

/*-
#define F(x,y,z)        (((x) & (y))  |  ((~(x)) & (z)))
#define G(x,y,z)        (((x) & (z))  |  ((y) & (~(z))))
*/

/*
 * As pointed out by Wei Dai, the above can be simplified to the code
 * below.  Wei attributes these optimizations to Peter Gutmann's
 * SHS code, and he attributes it to Rich Schroeppel.
 */
#define F(b,c,d)        ((((c) ^ (d)) & (b)) ^ (d))
#define G(b,c,d)        ((((b) ^ (c)) & (d)) ^ (c))
#define H(b,c,d)        ((b) ^ (c) ^ (d))
#define I(b,c,d)        (((~(d)) | (b)) ^ (c))

#define R0(a,b,c,d,k,s,t) { \
        a+=((k)+(t)+F((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };\

#define R1(a,b,c,d,k,s,t) { \
        a+=((k)+(t)+G((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };

#define R2(a,b,c,d,k,s,t) { \
        a+=((k)+(t)+H((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };

#define R3(a,b,c,d,k,s,t) { \
        a+=((k)+(t)+I((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };
