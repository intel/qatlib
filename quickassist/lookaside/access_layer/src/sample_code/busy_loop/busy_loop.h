/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
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
