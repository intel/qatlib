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
#ifndef BUSY_LOOP_H
#define BUSY_LOOP_H

#ifdef USER_SPACE
#include <stdint.h>
#else
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/hardirq.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#endif

#define BUSY_LOOP_INCREMENT (20)

#define ERROR_MARGIN (1)
#define PERCENT_TPUT_VARIANCE (1)

#ifdef USER_SPACE
void __attribute__((noinline)) busyLoop(uint32_t n, volatile uint32_t *var);
unsigned long long __attribute__((noinline))
busyLoop2(uint32_t n, volatile uint32_t *var);
#else
void busyLoop(uint32_t n, volatile uint32_t *var);
unsigned long long busyLoop2(uint32_t n, volatile uint32_t *var);
#endif
unsigned long long getTimeStampTime(void);
unsigned long long getTimeStampTime2(void);

extern uint32_t busyLoopCounter_g;
extern unsigned int useCpuid;

uint8_t withinMargin(uint32_t baseVal, uint32_t currentVal, uint32_t margin);
#ifdef __x86_64__
static inline uint64_t busyLoopTimeStamp(void)
{

    unsigned cycles_low, cycles_high;
    if (useCpuid)
    {
        unsigned cycles_low1, cycles_high1;
#ifdef KERNEL_SPACE
        unsigned long flags;
        preempt_disable();
        local_irq_save(flags);
#endif
        __asm__ volatile("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(cycles_high),
                           "=r"(cycles_low)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
        __asm__ volatile("RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         "CPUID\n\t"
                         : "=r"(cycles_high1),
                           "=r"(cycles_low1)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
        __asm__ volatile("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(cycles_high),
                           "=r"(cycles_low)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
        __asm__ volatile("RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         "CPUID\n\t"
                         : "=r"(cycles_high1),
                           "=r"(cycles_low1)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
        __asm__ volatile("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(cycles_high),
                           "=r"(cycles_low)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
#ifdef KERNEL_SPACE
        raw_local_irq_restore(flags);
        preempt_enable();
#endif
    }
    else
    {
        __asm__ volatile("RDTSCP\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(cycles_high),
                           "=r"(cycles_low)::"%rax",
                           "%rbx",
                           "%rcx",
                           "%rdx");
    }
    return (((uint64_t)cycles_high << 32) | cycles_low);
}
#else
static inline uint64_t busyLoopTimeStamp(void)
{
    return (uint64_t)0;
}
#endif /*__x64_64__*/

#endif /* End BUSY_LOOP_H */
