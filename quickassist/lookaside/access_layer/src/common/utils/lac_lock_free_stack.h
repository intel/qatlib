#ifndef LAC_LOCK_FREE_STACK_H_1
#define LAC_LOCK_FREE_STACK_H_1

/*******************************************************************************
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
 * @lac_lock_free_stack.h
 *
 * This file provides a lock-free stack implementation.
 * There is an assumption that effective virtual address size is 57-bit,
 * which is true for Linux user space applications in 32/64-bit modes.
 * Stack is usable on 48-bit and 57-bit platforms.
 *
 ******************************************************************************/

#ifndef KERNEL_SPACE
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include "lac_mem_pools.h"

static inline lac_mem_blk_t *pop(lock_free_stack_t *stack)
{
    pointer_t old_top;
    pointer_t new_top;
    lac_mem_blk_t *next;

    do
    {
        old_top.atomic = stack->top.atomic;
        next = old_top.ptr;
        if (NULL == next)
            return next;

        new_top.ptr = next->pNext;
        new_top.ctr = old_top.ctr + 1;
    } while (!__sync_bool_compare_and_swap(
        &stack->top.atomic, old_top.atomic, new_top.atomic));

    return next;
}

static inline void push(lock_free_stack_t *stack, lac_mem_blk_t *val)
{
    pointer_t new_top;
    pointer_t old_top;

    do
    {
        old_top.atomic = stack->top.atomic;
        val->pNext = old_top.ptr;
        new_top.ptr = val;
        new_top.ctr = old_top.ctr + 1;
    } while (!__sync_bool_compare_and_swap(
        &stack->top.atomic, old_top.atomic, new_top.atomic));
}

static inline lock_free_stack_t _init_stack(void)
{
    lock_free_stack_t stack = {{{0}}};
    return stack;
}

static inline lac_mem_blk_t *top(lock_free_stack_t *stack)
{
    pointer_t old_top = stack->top;
    lac_mem_blk_t *next = old_top.ptr;
    return next;
}

#endif
