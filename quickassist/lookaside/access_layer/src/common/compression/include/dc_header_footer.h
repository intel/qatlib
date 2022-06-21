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
 * @file dc_header_footer.h
 *
 * @ingroup Dc_DataCompression
 *
 * @description
 *      Definition of the Data Compression header and footer parameters.
 *
 *****************************************************************************/
#ifndef DC_HEADER_FOOTER_H_
#define DC_HEADER_FOOTER_H_

/* Header and footer sizes for Zlib and Gzip */
#define DC_ZLIB_HEADER_SIZE (2)
#define DC_GZIP_HEADER_SIZE (10)
#define DC_ZLIB_FOOTER_SIZE (4)
#define DC_GZIP_FOOTER_SIZE (8)

/* Values used to build the headers for Zlib and Gzip */
#define DC_GZIP_ID1 (0x1f)
#define DC_GZIP_ID2 (0x8b)
#define DC_GZIP_FILESYSTYPE (0x03)
#define DC_ZLIB_WINDOWSIZE_OFFSET (4)
#define DC_ZLIB_FLEVEL_OFFSET (6)
#define DC_ZLIB_HEADER_OFFSET (31)

/* Compression level for Zlib */
#define DC_ZLIB_LEVEL_0 (0)
#define DC_ZLIB_LEVEL_1 (1)
#define DC_ZLIB_LEVEL_2 (2)
#define DC_ZLIB_LEVEL_3 (3)

/* CM parameter for Zlib */
#define DC_ZLIB_CM_DEFLATE (8)

/* Type of Gzip compression */
#define DC_GZIP_FAST_COMP (4)
#define DC_GZIP_MAX_COMP (2)

#endif /* DC_HEADER_FOOTER_H_ */
