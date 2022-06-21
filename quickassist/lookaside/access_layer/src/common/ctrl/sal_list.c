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
 *****************************************************************************
 * @file sal_list.c
 *
 * @ingroup SalCtrl
 *
 * List implementations for SAL
 *
 *****************************************************************************/

#include "lac_mem.h"
#include "lac_list.h"

CpaStatus SalList_add(sal_list_t **list, sal_list_t **tail, void *pObj)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    sal_list_t *new_element = NULL;

    if (NULL == *list)
    {
        /* First element in list */
        *list = osalMemAlloc(sizeof(sal_list_t));
        if (NULL == *list)
        {
            LAC_LOG_ERROR("Failed to allocate memory for list");
            status = CPA_STATUS_RESOURCE;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            (*list)->next = NULL;
            (*list)->pObj = pObj;
            *tail = *list;
        }
    }
    else
    {
        /* add to tail of the list */
        new_element = osalMemAlloc(sizeof(sal_list_t));
        if (NULL == new_element)
        {
            LAC_LOG_ERROR("Failed to allocate memory for list");
            status = CPA_STATUS_RESOURCE;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            new_element->pObj = pObj;
            new_element->next = NULL;

            (*tail)->next = new_element;

            *tail = new_element;
        }
    }

    return status;
}

void *SalList_getObject(sal_list_t *list)
{
    if (list == NULL)
    {
        return NULL;
    }

    return list->pObj;
}

void SalList_delObject(sal_list_t **list)
{
    if (*list == NULL)
    {
        return;
    }

    (*list)->pObj = NULL;
    return;
}

void *SalList_next(sal_list_t *list)
{
    return list->next;
}

void SalList_free(sal_list_t **list)
{
    sal_list_t *next_element = NULL;
    void *pObj = NULL;
    while (NULL != (*list))
    {
        next_element = SalList_next(*list);
        pObj = SalList_getObject((*list));
        LAC_OS_FREE(pObj);
        LAC_OS_FREE(*list);
        *list = next_element;
    }
}

void SalList_del(sal_list_t **head_list,
                 sal_list_t **pre_list,
                 sal_list_t *list)
{
    void *pObj = NULL;
    if ((NULL == *head_list) || (NULL == *pre_list) || (NULL == list))
    {
        return;
    }
    if (*head_list == list)
    { /* delete the first node in list */
        *head_list = list->next;
    }
    else
    {
        (*pre_list)->next = list->next;
    }
    pObj = SalList_getObject(list);
    LAC_OS_FREE(pObj);
    LAC_OS_FREE(list);
    return;
}
