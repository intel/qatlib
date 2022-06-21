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
 ***************************************************************************
 * @file sal_misc_error_stats.h
 *
 * @ingroup SalMiscErrStats
 *
 * The file contains functions handles miscellaneous error global counter
 *
 ***************************************************************************/

#ifndef SAL_MISC_ERR_STATS_H
#define SAL_MISC_ERR_STATS_H

#ifndef KERNEL_SPACE
#define SAL_MISC_ERR_STATS_INC(err, service)                                   \
    do                                                                         \
    {                                                                          \
        if (ERR_CODE_MISC_ERROR == (Cpa8S)err && service)                      \
        {                                                                      \
            Sal_IncMiscErrStats(service);                                      \
        }                                                                      \
    } while (0)
#else
#define SAL_MISC_ERR_STATS_INC(err, service)
#endif

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to increase misc error statistics.
 *
 * @param[in] pService         pointer to service instance.
 *
 * @assumptions
 *      Called when misc error reported by firmware.
 * @sideEffects
 *      None
 * @reentrant
 *      None
 * @threadSafe
 *      Yes
 *
 ******************************************************************/

CpaStatus Sal_IncMiscErrStats(sal_service_t *pService);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to get the misc error statistics.
 *
 * @param[in] pService         pointer to service instance.
 * @param[out] pMiscStats      pointer to get misc counter.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 ******************************************************************/
CpaStatus Sal_GetMiscErrStats(sal_service_t *pService, OsalAtomic *pMiscStats);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to initialise misc error statistics and
 *    create misc error stats file.
 *
 * @param[in] pStats         pointer to statistics instance.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      None
 * @threadSafe
 *      None
 *
 ******************************************************************/
CpaStatus Sal_InitMiscErrStats(sal_statistics_collection_t *pStats);

/*******************************************************************
 * @ingroup SalMiscErrStats
 * @description
 *    This function is used to clear misc error statistics and
 *    remove the misc error stats file.
 *
 * @param[in] pService         pointer to service instance.
 *
 * @assumptions
 *      None
 * @sideEffects
 *      None
 * @reentrant
 *      Yes
 * @threadSafe
 *      Yes
 *
 ******************************************************************/
CpaStatus Sal_CleanMiscErrStats(sal_service_t *pService);

#endif
