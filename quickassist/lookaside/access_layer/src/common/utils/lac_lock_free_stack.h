#ifndef LAC_LOCK_FREE_STACK_H_1
#define LAC_LOCK_FREE_STACK_H_1

/*******************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 * @lac_lock_free_stack.h
 *
 * This file provides a lock-free stack implementation.
 * There is an assumption that effective virtual address size is 57-bit,
 * which is true for Linux user space applications in 32/64-bit modes.
 * Stack is usable on 48-bit and 57-bit platforms.
 *
 ******************************************************************************/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
