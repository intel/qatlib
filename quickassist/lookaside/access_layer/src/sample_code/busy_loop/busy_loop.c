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

#ifdef KERNEL_SPACE
EXPORT_SYMBOL(getTimeStampTime2);
EXPORT_SYMBOL(useCpuid);
EXPORT_SYMBOL(setUseCpuid);
EXPORT_SYMBOL(getTimeStampTime);
EXPORT_SYMBOL(testBusyLoop);
EXPORT_SYMBOL(testBusyLoop2);
EXPORT_SYMBOL(withinMargin);
EXPORT_SYMBOL(setBusyLoopCounter);
EXPORT_SYMBOL(busyLoop);
EXPORT_SYMBOL(busyLoop2);
EXPORT_SYMBOL(busyLoopCounter_g);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Sample Code");
#endif
