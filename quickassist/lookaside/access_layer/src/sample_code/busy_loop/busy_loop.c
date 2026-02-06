/****************************************************************************
 *
 *   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2007-2026 Intel Corporation
 * 
 *   These contents may have been developed with support from one or more
 *   Intel-operated generative artificial intelligence solutions.
 *
 ***************************************************************************/
#ifdef USER_SPACE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#else

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/types.h>
#include <asm/div64.h>

#endif

#include "busy_loop.h"

unsigned int useCpuid = 1;

#ifdef USER_SPACE
#define do_div(n, base) (n = n / base)

#define PRINT(args...)                                                         \
    {                                                                          \
        printf(args);                                                          \
    }
#else
#define PRINT(args...)                                                         \
    {                                                                          \
        printk(KERN_CONT args);                                                \
    }
#endif

#define SCALING_FACTOR (1000)

uint32_t busyLoopCounter_g = 0;

void setUseCpuid(unsigned int a);
void testBusyLoop(uint32_t n);
void testBusyLoop2(uint32_t n);
void setBusyLoopCounter(uint32_t busyLoopCounter);

#ifdef USER_SPACE
void __attribute__((noinline)) busyLoop(uint32_t n, volatile uint32_t *var)
{
    uint32_t k = 0;
    for (k = 0; k < n; k++)
    {
        (*var) = 1;
    }
}
unsigned long long __attribute__((noinline))
busyLoop2(uint32_t n, volatile uint32_t *var)
{
    uint32_t k = 0;
    unsigned long long totalBusyLoopCycles = 0, startBusyLoop = 0,
                       endBusyLoop = 0;
    busyLoopTimeStamp();

    startBusyLoop = busyLoopTimeStamp();
    for (k = 0; k < n; k++)
    {
        (*var) = 1;
    }
    endBusyLoop = busyLoopTimeStamp();

    totalBusyLoopCycles = endBusyLoop - startBusyLoop;
    return totalBusyLoopCycles;
}

#else
void busyLoop(uint32_t n, volatile uint32_t *var)
{
    uint32_t k = 0;
    for (k = 0; k < n; k++)
    {
        (*var) = 1;
    }
    return;
}

unsigned long long busyLoop2(uint32_t n, volatile uint32_t *var)
{
    uint32_t k = 0;
    unsigned long long totalBusyLoopCycles = 0, startBusyLoop = 0,
                       endBusyLoop = 0;
    // busyLoopTimeStamp();

    startBusyLoop = busyLoopTimeStamp();
    for (k = 0; k < n; k++)
    {
        (*var) = 1;
    }
    endBusyLoop = busyLoopTimeStamp();

    totalBusyLoopCycles = endBusyLoop - startBusyLoop;
    return totalBusyLoopCycles;
}
#endif

void setUseCpuid(unsigned int a)
{
    useCpuid = a;
    return;
}

void setBusyLoopCounter(uint32_t busyLoopCounter)
{
    busyLoopCounter_g = busyLoopCounter;
    return;
}

unsigned long long getTimeStampTime(void)
{
    unsigned int i = 0;
    unsigned long long totalBusyLoopCycles = 0, startBusyLoop = 0;

    for (i = 0; i < 0x10000; i++)
    {
        startBusyLoop = busyLoopTimeStamp();
        totalBusyLoopCycles += busyLoopTimeStamp() - startBusyLoop;
    }
    totalBusyLoopCycles = totalBusyLoopCycles >> 16;
    return totalBusyLoopCycles;
}

unsigned long long getTimeStampTime2(void)
{
    unsigned long long totalBusyLoopCycles = 0, startBusyLoop = 0;

    startBusyLoop = busyLoopTimeStamp();
    totalBusyLoopCycles = busyLoopTimeStamp() - startBusyLoop;
    return totalBusyLoopCycles;
}

void testBusyLoop(uint32_t n)
{
    uint32_t var = 0;
    uint32_t numBusyLoops = 0;
    unsigned long long totalBusyLoopCycles = 0, startBusyLoop = 0,
                       endBusyLoop = 0;
    busyLoopTimeStamp();

    startBusyLoop = busyLoopTimeStamp();
    for (numBusyLoops = 0; numBusyLoops < n; numBusyLoops++)
    {
        busyLoop(busyLoopCounter_g, &var);
    }
    endBusyLoop = busyLoopTimeStamp();

    totalBusyLoopCycles = endBusyLoop - startBusyLoop;
#ifdef USER_SPACE
    PRINT("Total Cycles %llu\n", totalBusyLoopCycles);
#else
    PRINT("Total Cycles %llu\n", totalBusyLoopCycles);
#endif
}

void testBusyLoop2(uint32_t n)
{
    uint32_t var = 0;
    uint32_t numBusyLoops = 0;
    unsigned long long totalBusyLoopCycles = 0;
    busyLoopTimeStamp();

    for (numBusyLoops = 0; numBusyLoops < n; numBusyLoops++)
    {
        totalBusyLoopCycles += busyLoop2(busyLoopCounter_g, &var);
    }
#ifdef USER_SPACE
    PRINT("Total Cycles %llu\n", totalBusyLoopCycles);
#else
    PRINT("Total Cycles %llu\n", totalBusyLoopCycles);
#endif
}

uint8_t withinMargin(uint32_t baseVal, uint32_t currentVal, uint32_t margin)
{
    uint32_t difference = 0;
    if (currentVal >= baseVal)
    {
        return 1;
    }

    difference = baseVal - currentVal;
    difference *= SCALING_FACTOR;
    do_div(difference, baseVal);
    if (difference <= margin)
    {
        return 1;
    }
    return 0;
}

