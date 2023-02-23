/******************************************************************************
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
 *****************************************************************************/

===============================================================================

Intel(r) DH895xCC Sample Code for Security Applications on Intel(r)
QuickAssist(r) Technology

Intel(r) C6xx Sample Code for Security Applications on Intel(r)
QuickAssist(r) Technology

Intel(r) C3xxx Sample Code for Security Applications on Intel(r)
QuickAssist(r) Technology

Intel(r) D15xx Sample Code for Security Applications on Intel(r)
QuickAssist(r) Technology

Intel(r) C4xxx Sample Code for Security Applications on Intel(r)
QuickAssist(r) Technology

February, 2020

===============================================================================

Reference
=========

 - Intel(r) Communications Chipset 89xx Series Software for Linux*
   Getting Started Guide

 - Intel(r) QuickAssist Technology Software for Linux* - Getting Started Guide - appropriate HW version

 - Intel(r) QuickAssist Technology Software for Linux* - Programmer's Guide - appropriate HW version

===============================================================================


Installing and Running the Security Sample Performance Tests

===============================================================================

1) General
This is how to generate and run sample code for security on Linux.

Note that Performance sample code is available only for Linux.

The autoconf script is used to build the sample code and driver. The
output of which is created in

<INSTALL_PATH>/quickassist/lookaside/access_layer/src/sample_code/build

The following autoconf instructions are used to install driver
cd <INSTALL_PATH>/
./configure
make uninstall
make install

The following autoconf instruction is used to install sample code

make samples-install

To build and install sample code in SRIOV environment

The following autoconf instructions are used to install driver and samplecode in host machine

./configure --enable-icp-sriov=host
make install
make samples-install

The following autoconf instructions are used to install driver and samplecode in guest machine

./configure --enable-icp-sriov=guest
make install
make samples-install

Note: Refer to the relevant Getting Started Guide for Virtualization instructions

The autoconf automatically performs building sample code.
The Calgary Corpus files are installed at the location defined in <SAMPLE_CODE_CORPUS_PATH>

===============================================================================

2) Performance Samplecode Execution Instructions

To run this performance sample code, on Linux use the following command in
user space to execute the user space app

./cpa_sample_code

NOTE: All OS security components must be initialized before attempting to run
the module.

The following tests will then run:

Cipher Encrypt AES128-CBC: 100000* operations per crypto instance of packet
sizes 64, 128, 256, 204, 512, 1024, 1152, 2048, 4096, IMIX**

Algorithm Chaining- AES128-CBC HMAC-SHA1: 100000 operations per crypto instance
of packet sizes 64, 128, 256, 204, 512, 1024, 1152, 2048, 4096, IMIX**

Cipher Encrypt AES256-CBC: 100000* operations per crypto instance of packet
sizes 64, 128, 256, 204, 512, 1024, 1152, 2048, 4096, IMIX**

Algorithm Chaining- AES256-CBC HMAC-SHA512: 100000 operations per crypto
instance of packet sizes 64, 128, 256, 204, 512, 1024, 1152, 2048, 4096, IMIX**

Algorithm Chaining- AES256-CBC HMAC-AES-XCBC: 100000 operations per crypto
instance of packet sizes 64, 128, 256, 204, 512, 1024, 1152, 2048, 4096, IMIX**

RSA CRT Decrypt 1024, 2048 and 4096 bit: 10000 operations each

DH 180bit exponent with 1024, 2048 and 4096 bit modulus

DSA L/N Pair of 1024/160 bit: 10000 operations

ECDSA 192 bit binary nist curve: 10000 operations

Deflate Compression/Decompression Level 1 & 3 on the the Calgary Corpus using
8182 byte buffers. 64k decompression of zlib compresses data if the USE_ZLIB
option is set

Once the test has completed, "Sample Code Complete" is
displayed.

*Note the number of operations sent is on a per thread basis.
The number of threads is controlled by the lower of:
    the number of cores
    the number of crypto instance

Based on plaform default value for above parameters are configured in driver configuration file

**IMIX is a mixture of packet sizes 40%-64Byte 20%-752Byte 35% 1504Byte
5%-8892Byte. of the total submissions


The throughput and operations per second output maybe inaccurate for less than
100000 and 10000 submissions per thread for symmetric and asymmetric respectively.

By default the sample code is set to submit the minimum number of submissions
required for an accurate output.

If sample code is to be used to get reliable performance measures one of the
following needs to be applied prior to running sample code tests:

o   Intel SpeedStep(r) Technology needs to be disabled in BIOS


===============================================================================

3) Performance Module Control

cpa_sample_code user space application supports optional
parameters for controlling which tests run and how many
iterations of each test are executed.

These optional parameters are passed during module loading.

Example:
./cpa_sample_code signOfLife=1 runTests=64

signOfLife parameter is set the minimum number iterations to be executed with below values
    cyNumBuffers
    cySymLoops
    cyAsymLoops
    dcLoops

cySymLoops is the number of iterations of Symmetric operations to be executed,
which affects the running time of the following tests
    a) All Algorithm Chaining tests
    b) All Cipher Encrypt tests
    c) Hash HMAC-SHA1

cyAsymLoops is the number of iterations of Asymmetric operations to be executed,
which affects the running time of the following tests
    a) RSA CRT Decrypt
    b) DSA
    c) ECDSA
    d) DH

dcLoops is the number of iterations of Compression operations to be executed.

The runTests parameter is a bit masked variable used to control which tests are
 to be executed.

    runTests=1                          Run symmetric tests.
    runTests=2                          Run RSA test.
    runTests=4                          Run DSA test.
    runTests=8                          Run ECDSA test.
    runTests=16                         Run DH test
    runTests=32                         Run Stateless Compression test.
    runTests=63                         Run all tests. (default)
    runTests=32 runStateful=1           Run both stateful and stateless compression test.
    runTests=32 runStateful=1 useCnv=1  Run CNV test.
    runTests=1024                       Run SM2 test.
    runTests=2048                       Run SM3&4 test.

The current default is runTests=63, run all tests.

The default configFileVer=2 is currently the only supported mode of operation. If the
wrong version of config file is used the sample code will issue an error
message and fail to find any logical instances.

getLatency is an optional parameter which will enable Latency measurement.
Currently latency measurement is supported only for symmetric cipher i.e. runTest=1
and Compression tests i.e. runTest=32.
If signOfLife parameter is passed, latency will not be captured.
Example:
./cpa_sample_code runTests=1 getLatency=1

getOffloadCost is an optional parameter which will enable computation of offload cost.
The cost is measured in the number of CPU cycles consumed and the results may vary
from platform to plarform as Cost Of Offload (COO) is platform dependent.
If signOfLife parameter is passed, COO will not be captured.
Example:
./cpa_sample_code runTests=32 getOffloadCost=1

Note: getLatency and getOffloadCost are mutually exclusive i.e. Only one can be
enabled for a particular invocation of cpa_sample_code application.
The measurement should be performed with just one active sample code thread.
i.e.NumberCyInstances and NumberDcInstances shoule be set to 1 in the driver
configuration file under SSL section. Also only one device should be active at the
time of measurement.
Results may vary depending on platform settings like CPU energy savings, turbo boost, etc.
It is not recommended to run latency or COO inside of VM as the results might be affected
by hypervisor policies.
Both getLatency and getOffloadCost are added to give an idea about the Latency
and COO, however because of the range of factors which can impact the values,
those should be taken with considerations.

useStaticPrime is an optional parameter with default of 1(on), which indicates
whether RSA performance test execution should use prepared primes during
parameter generation or generate primes at runtime.
Note this value has no bearing on the eventual
performance metrics presented upon completion of RSA tests.

===============================================================================

4) Known Issues

This is sample code and all invalid cases are not fully covered.



Legal/Disclaimers
===================

INFORMATION IN THIS DOCUMENT IS PROVIDED IN CONNECTION WITH INTEL(R) PRODUCTS.
NO LICENSE, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, TO ANY INTELLECTUAL
PROPERTY RIGHTS IS GRANTED BY THIS DOCUMENT. EXCEPT AS PROVIDED IN INTEL'S
TERMS AND CONDITIONS OF SALE FOR SUCH PRODUCTS, INTEL ASSUMES NO LIABILITY
WHATSOEVER, AND INTEL DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY, RELATING TO
SALE AND/OR USE OF INTEL PRODUCTS INCLUDING LIABILITY OR WARRANTIES RELATING
TO FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR INFRINGEMENT OF ANY
PATENT, COPYRIGHT OR OTHER INTELLECTUAL PROPERTY RIGHT. Intel products are
not intended for use in medical, life saving, life sustaining, critical control
 or safety systems, or in nuclear facility applications.

Intel may make changes to specifications and product descriptions at any time,
without notice.

(C) Intel Corporation 2018

* Other names and brands may be claimed as the property of others.

===============================================================================
