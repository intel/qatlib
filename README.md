![Linux build with gcc](https://github.com/intel/qatlib/actions/workflows/linux_build_gcc.yml/badge.svg)
![CodeQL scan](https://github.com/intel/qatlib/actions/workflows/codeql.yml/badge.svg)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/intel/qatlib/badge)](https://api.securityscorecards.dev/projects/github.com/intel/qatlib)

# Intel&reg; QuickAssist Technology Library (QATlib)

## Table of Contents

- [Revision History](#revision-history)
- [Overview](#overview)
- [Features](#features)
- [Insecure Algorithms](#insecure-algorithms)
- [Deprecated Features & Planned Deprecations](#deprecated-features--planned-deprecations)
- [Setup](#setup)
- [Supported Devices](#supported-devices)
- [Limitations](#limitations)
- [Environmental Assumptions](#environmental-assumptions)
- [Examples](#examples)
- [Open Issues](#open-issues)
- [Resolved Issues](#resolved-issues)
- [Licensing](#licensing)
- [Legal](#legal)
- [Terminology](#terminology)

## Revision History

| Date      |     Doc Revision      | Version |   Details |
|----------|:-------------:|------:|:------|
| July 2024 | 013 | 24.02 | - Doc update only. Updated this table to say that support for the GEN4 402xx device was added in the 24.02 release. Added link to more details in Supported Devices section. |
| February 2024 | 012 | 24.02 | - Added Heartbeat support. <br> - Added support for QAT GEN 5 devices, including support for a range of crypto wireless algorithms. <br> - RAS - Device error reset and recovery handling. <br> - Bug Fixes. See [Resolved Issues](#resolved-issues). |
| November 2023 | 011 | 23.11 | - Support DC NS (NoSession) APIs.  <br> - Support  DC compressBound APIs. <br> - Support Symmetric Crypto SM3 & SM4. <br> - Support Asymmetric Crypto SM2. <br> - Bug Fixes. See [Resolved Issues](#resolved-issues). |
| August 2023 | 010 | 23.08 | - Removal of following insecure algorithms: Diffie-Hellman and Elliptic curves less than 256-bits. <br> - Additional configuration profiles, including sym which facilitates improved symmetric crypto performance. <br> - DC Chaining (Hash then compress) <br> - Bug Fixes. See [Resolved Issues](#resolved-issues). <br> - The shared object version is changed from 3->4. |
| February 2023 | 009 | 23.02 | - Added configuration option --enable-legacy-algorithms to use these insecure crypto algorithms and disabled them by default (AES-ECB, SHA-1, SHA2-224, SHA3-224, RSA512/1024/1536, DSA)<br>- Refactored code in quickassist/utilities/libusdm_drv<br>- Bugfixes<br>- Updated documentation with configuration and tuning information |
| November 2022 | 008 | 22.07.2 | - Changed from yasm to nasm for assembly compilation<br> - Added configuration option to use C implementation of soft CRC implementation instead of asm<br>- Added support for pkg-config<br>- Added missing lock around accesses to some global data in qatmgr |
| October 2022 | 007 | 22.07.1 | - Fix for QATE-86605 |
| July 2022 | 006 | 22.07 | - Added support for lz4/lz4s compression algorithms<br>- Added support for Compression End-to-end (E2E) integrity check<br>- Added support for PKE generic point multiply<br>- Updated QAT APIs (as a result the shared object version  changed from 2->3). <br>- Enabled CPM2.0b<br>- Split rpm package |
| November 2021 | 005 | 21.11 | - Added qatlib-tests rpm package<br>- Added option to configure script to skip building sample code |
| August 2021 | 004 | 21.08 | - Added support for deflate compression - Compress and Verify (CnV) and Compress and Verify and Recover (CnVnR)<br>- Added Physical Function to Virtual Function (PFVF) communication support |
| May 2021 | 003 | 21.05 | - Added support for AES-CCM 192/265<br>- Added support for SHA3-224/384/512 (no partials support)<br>- Added support for ChaCha20-Poly1305<br>- Added support for PKE 8K (RSA, DH, ModExp, ModInv)<br>- Fixed device enumeration on different nodes<br>- Fixed pci_vfio_set_command for 32 bit builds |
| November 2020 | 002 | 20.10 | - Fixed service stopping during uninstallation<br>- Fixed "Cannot open /sys/kernel/iommu_groups/vfio/devices/" error<br>- Fixes based on static code analysis<br>- Fixes based on secure code reviews<br>- Refactored logging mechanism<br>- Updated library versioning scheme<br>- Improvements to make install target<br>- Fix so service file installed in /usr/lib64 can be properly detected<br>- Remove execute permissions from non-executable files<br>- Clarified documentation of licensing<br>- Removed libudev dependency from the package<br>- Removed OpenSSL/libcrypto extracts, instead link against system OpenSSL/libcrypto |
| August 2020 | 001 | 20.08 | - Initial Release |

## Overview
Intel(R) QuickAssist Technology (Intel(R) QAT) provides
hardware acceleration for offloading security, authentication and
compression services from the CPU, thus significantly increasing
the performance and efficiency of standard platform solutions.

Its services include symmetric encryption and authentication,
asymmetric encryption, digital signatures, RSA, DH and ECC, and
lossless data compression.

This package provides user space libraries that allow access to
Intel(R) QuickAssist devices and expose the Intel(R) QuickAssist APIs and
sample codes.

## Features

The following services are available in qatlib via the QuickAssist API:
* Symmetric (Bulk) Cryptography
  * Ciphers ([AES-ECB](#insecure-algorithms), AES-CBC, AES-CTR (no partials support),
    AES-XTS (no partials support), AES-GCM, AES-CCM (192/256), [SM4-ECB](#insecure-algorithms),
    SM4-CBC, SM4-CTR)
  * Message digest/hash ([SHA1](#insecure-algorithms), SHA2 ([224](#insecure-algorithms)/256/384/512),
    SHA3 ([224](#insecure-algorithms)/256/384/512) (no partials support), SM3) and
    authentication (AES-CBC-MAC, AES-XCBC-MAC, AES-CMAC-128)
  * Algorithm chaining (one cipher and one hash in a single operation)
  * Authenticated encryption (CCM-128 (no partials support),
    GCM (128/192/256) (no partials support), GMAC (no partials support)
    and ChaCha20-Poly1305)
* KeyGen
  * TLS1.2
  * TLS1.3
  * HKDF
  * MGF1
* Asymmetric (Public Key) Cryptography
  * Modular exponentiation and modular inversion up to 8192 bits
  * [Diffie-Hellman (DH)](#insecure-algorithms) key generation phase 1 and 2 up to 8192 bits
  * [RSA](#insecure-algorithms) key generation, encryption/decryption and digital signature
    generation/verification up to 8192 bits
  * [DSA](#insecure-algorithms) parameter generation and digital signature generation/verification
  * Elliptic Curve Cryptography: ECDSA, ECDHE, Edwards Montgomery curves
  * Generic point multiply
  * SM2
* Compression
  * Deflate
  * lz4/lz4s
  * Compress and Verify (CnV)
  * Compress and Verify and Recover (CnVnR)
  * End-to-end (E2E) integrity check
  * DC compressBound APIs
  * DC NS (No Session) APIs
* Compression Chaining (Deflate only)
  * Hash then compress
* Wireless Algorithms (supported on QAT GEN 5 devices)
  * Ciphers (SNOW3G-UEA2, ZUC-128, ZUC-256, AES-F8)
  * Message digest/hash (SNOW3G-UIA2, ZUC-128, ZUC-256) and authentication (AES-CMAC-128, AES-CMAC-192, AES-CMAC-256)

This package includes:
* libqat: user space library for QAT devices exposed via the vfio kernel driver
* libusdm: user space library for memory management
* qatmgr: user space daemon for device management
* Sample codes: applications to demo usage of the libs

## Insecure Algorithms
The following algorithms are considered insecure and are disabled by default.
* AES-ECB
* SHA-1
* SHA2-224
* SHA3-224
* RSA512/1024/1536
* DSA
* Diffie-Helman
* Elliptic Curve Cryptography algorithms with less 256 bits
* SM4-ECB

To enable these algorithms, use the following configuration option:
   * `--enable-legacy-algorithms`

## Deprecated Features & Planned Deprecations
* The following configuration option will be deprecated after 2023:
  * `--enable-legacy-lib-names`

## Setup
Please refer to [INSTALL](INSTALL) for details on installing the library.

## Supported Devices
* 4xxx, 401xx and 402xx (QAT GEN 4 devices)
* 420xx (QAT GEN 5 devices)

Earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.) are not
supported. Please refer to [QATlib User’s Guide](https://intel.github.io/quickassist/qatlib/requirements.html#supported-devices) for more information
on supported devices.

## Limitations
* If an error occurs on the host driver (Heartbeat, Uncorrectable error) it
  will not be communicated to the library.
* For simplicity, only one configuration file is used by qatlib. For guidance
  on how to use this to allocate resources for processes, please refer to
  Configuration and Tuning section in [QATlib User’s Guide](https://intel.github.io/quickassist/qatlib/index.html).

The following features are not currently supported:
* Dynamic instances
* Intel® Key Protection Technology (KPT)
* Event driven polling
* More than 16 processes per end point (16 is the maximum)
* accumulateXXHash when combined with autoSelectBestHuffmanTree
* accumulateXXHash in Decompression or Combined sessions
* integrityCrcCheck for Compression direction requests

## Environmental Assumptions

The following assumptions are made concerning the deployment environment:
* Users within the same processing domain must be trusted, i.e.: on the same
  host or within the same virtual machine, users must trust each other.
* The library can be used by unprivileged users if those users are included in
  the 'qat' group.
* DRAM is considered to be inside the trust boundary. The typical memory
  protection schemes provided by the Intel architecture processor and memory
  controller, and by the operating system, prevent unauthorized access to these
  memory regions.
* A QuickAssist kernel driver for the supported device is installed, which has
  discovered and initialized the device, exposing the VFs. This driver is
  included in the Linux kernel, see [QATlib User’s Guide](https://intel.github.io/quickassist/RN/In-Tree/in_tree_firmware_RN.html#qat-kernel-driver-releases-features) for information about
  which kernel to use.

## Examples
Example applications that showcase usage of the QAT APIs are included in the
package (quickassist/lookaside/access_layer/src/sample_code).
Please refer to [Intel® QuickAssist Technology API Programmer's Guide](https://www.intel.com/content/www/us/en/content-details/709196/intel-quickassist-technology-api-programmer-s-guide.html).

## Open Issues
Known issues relating to the Intel® QAT software are described
in this section.

Issue titles follow the pattern:

    <Component> [Stepping] -  Description of issue
where: \<Component\> is one of the following:
* CY - Cryptographic
* DC - Compression
* EP - Endpoint
* GEN - General
* SYM DP - Symmetric Cryptography on Data Plane
* SR-IOV - Single Root I/O Virtualization
* FW - Firmware
* PERF - Performance

[Stepping] is an optional qualifier that identifies if the errata applies to a specific device stepping

| Issue ID | Description |
|-------------|------------|
| QATE-3241  | [CY - cpaCySymPerformOp when used with parameter checking may reveal the amount of padding.](#qate-3241) |
| QATE-41707 | [CY - Incorrect digest returned when performing a plain hash operation on input data of size 4GB or larger.](#qate-41707) |
| QATE-76073 | [GEN - If PF device configuration is modified without restarting qatmgr, undefined behavior may occur.](#qate-76073) |
| QATE-76698 | [GEN - Multi-process applications running in guest will fail when running with default Policy settings.](#qate-76698) |
| QATE-98551 | [GEN - On a multi-socket platform, there can be a performance degradation on the remote sockets.](#qate-98551) |

## QATE-3241
| Title      |       CY - cpaCySymPerformOp when used with parameter checking may reveal the amount of padding.        |
|----------|:-------------
| Reference # | QATE-3241 |
| Description | When Performing a CBC Decryption as a chained request using cpaCySymPerformOp it is necessary to pass a length of the data to MAC (messageLenToHashInBytes). With ICP_PARAM_CHECK enabled, this checks the length of data to MAC is valid and, if not, it aborts the whole operation and outputs an error on stderr. |
| Implication | The length of the data to MAC is based on the amount of padding. This should remain private and not be revealed. The issue is not observed when the length is checked in constant time before passing the value to the API. This is done by OpenSSL. |
| Resolution | 1. Build without ICP_PARAM_CHECK, but this opens the risk of buffer overrun. <BR> 2. Validate the length before using the API. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - Crypto |

## QATE-41707

| Title      |         CY -  Incorrect digest returned when performing a plain hash operation on input data of size 4GB or larger.      |
|----------|:-------------
| Reference # | QATE-41707 |
| Description | When performing a plain hash operation on input data size of 4GB or larger, incorrect digest is returned. |
| Implication | Incorrect digest is returned from a plane hash operation. |
| Resolution | There is no fix available. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - Crypto |

## QATE-76073
| Title      |         GEN - If PF device configuration is modified without restarting qatmgr, undefined behavior may occur.     |
|----------|:-------------
| Reference # | QATE-76073 |
| Description | When qatmgr is initialized, it reads the current configuration of the PF device. If the PF device configuration is modified without restarting the qatmgr, the updated device configuration is not comprehended by qatmgr. |
| Implication | Undefined behavior may occur. |
| Resolution | If PF device is reconfigured and reloaded, ensure to stop and start the qatmgr. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-76698
| Title      |         GEN - Multi-process applications running in guest will fail when running with default Policy settings.     |
|----------|:-------------
| Reference # | QATE-76698 |
| Description | The default Policy setting results in process receiving all available VFs allocated to guest operating system.  In the case of a multi-process application, failures will be observed as all available QAT resources are consumed by the first process. |
| Implication | Multi-process applications running in guest OS will fail with default Policy settings. |
| Resolution | If more than 1 process is needed in a guest OS, set POLICY=n (where n>0) in /etc/sysconfig/qat and restart qatmgr. The process will then receive n VFs. See RUNNING IN A VIRTUAL MACHINE / GUEST section of INSTALL for details. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-98551
| Title      |        GEN - On a multi-socket platform, there can be a performance degradation on the remote sockets. |
|----------|:-------------
| Reference # | QATE-98551 |
| Description | On a multi-socket platform, there can be a performance degradation on remote sockets. This can arise when either the threads are not affinitised to the core on the socket the device is on and/or the memory is not allocated on the appropriate NUMA node. |
| Implication | Performance on socket 0 is as expected, but does not scale proportionally on remote sockets. |
| Resolution | This will be fixed in a future release. In the meantime, applications on a multi-socket platform should configure threads using a QAT VF device on a remote socket to be affinitised to the core on that remote socket. Then the memory allocations are more likely to be done on the remote socket, with minimal performance impact. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## Resolved Issues
Resolved issues relating to the Intel® QAT software are described
in this section.

| Issue ID | Description |
|-------------|------------|
| QATE-97977 | [DC - 'Unable to get the physical address of Data Integrity buffer' error may be observed when using user-provided address translation functions.](#qate-97977) |
| QATE-94369 | [GEN - SELinux Preventing QAT Service Startup.](#qate-94369) |
| QATE-94286 | [GEN - Compression services not detected when crypto-capable VFs are added to VM.](#qate-94286) |
| QATE-95905 | [GEN - Fix build when building outside of main directory, issue #56](#qate-95905) |
| QATE-93844 | [DC - cpaDcLZ4SCompressBound is not returning correct value, which could lead to a buffer overflow.](#qate-93844)
| QATE-93278 | [GEN - sample_code potential seg-fault, issue #46](#qate-93278) |
| QATE-90845 | [GEN - QAT service fails to start, issue #38](#qate-90845) |
| QATE-78459 | [DC - cpaDcDeflateCompressBound API returns incorrect output buffer size when input size exceeds 477218588 bytes.](#qate-78459) |
| QATE-76846 | [GEN - Forking and re-initializing use-cases do not work](#qate-76846) |
| QATE-12241 | [CY - TLS1.2 with secret key lengths greater than 64 are not supported.](#qate-12241) |

## QATE-97977
| Title      |       DC - 'Unable to get the physical address of Data Integrity buffer' error may be observed when using user-provided address translation functions.        |
|----------|:-------------
| Reference # | QATE-97977 |
| Description | When using Integrity CRC feature (integrityCrcCheck in CpaDcOpData) and also user provided address translation functions (cpaDcSetAddressTranslation) the above error may be observed. |
| Implication | Compression request operations may fail in this scenario. |
| Resolution | Fixed in 24.02 |
| Affected OS | Linux |
| Driver/Module | CPM-IA - Data Compression |



## QATE-94369
| Title      |       GEN - SELinux Preventing QAT Service Startup        |
|----------|:-------------
| Reference # | QATE-94369 |
| Description | The qat service fails to start due to SELinux preventing the qat_init.sh script and qatmgr from accessing resources. The issue occurs when the system is running with SELinux enabled, causing insufficient permissions for the qat_init.sh script and qatmgr to function correctly. |
| Implication | This issue affects the proper functioning of the qat service on systems with SELinux enabled, potentially preventing QAT virtual functions (VFs) from functioning. |
| Resolution | The fix is not in the scope of qatlib. Instead there are three possible methods to handle this issue: <br> 1) Update selinux-policy as seen in https://github.com/fedora-selinux/selinux-policy/pull/1992 <br>2) Disable SElinux <br>3) Update mode to SElinux mode to permissive using following commands: <br>semanage permissive -a qatlib_exec_t<br>semanage permissive -a qatlib_t<br>The audit warnings may be generated, but qatlib will be allowed access to vfio devices. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-94286
| Title      |       GEN - Compression services not detected when crypto-capable VFs are also added to VM.        |
|----------|:-------------
| Reference # | QATE-94286 |
| Description | When configuring a system with different services on different QAT end-points, e.g. asym;sym on one and dc on another, and exposing only one of those Virtual Function (VF) types to the Virtual Machine (VM), the application works as expected. However, when VFs of more than one type are passed to the same VM, the application may only recognize one service-type, e.g. it may detect crypto instances, but not compression instances. There is an assumption that all VFs provide the same services if they come from the same PF. However, detecting which PF they come from is based on domain+bus, which is not always a valid assumption on a VM. |
| Implication | This issue prevents the detection of compression services in a virtualized environment when the default kernel configuration is used, and crypto and dc VFs are passed to the VM, potentially impacting the proper functioning of the system. |
| Resolution | Fixed in 23.11. <br>Temporary solution: use a custom libvirt XML file like QATE-76698 here: https://github.com/intel/qatlib/tree/main#qate-76698 . |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-95905
| Title      |       GEN - Fix build when building outside of main directory, issue #56        |
|----------|:-------------
| Reference # | QATE-95905 |<F3>
| Description | Fix build when building outside of main directory. Added changes to autoconfig to be able to build outside main directory. See [issue 56](https://github.com/intel/qatlib/issues/56). |
| Implication | A fatal error occurs when trying to build outside main directory. |
| Resolution | Fixed in 23.11. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-93844
| Title      |        DC - cpaDcLZ4SCompressBound is not returning correct value, which could lead to a buffer overflow.     |
|----------|:-------------
| Reference # | QATE-93844 |
| Description | CompressBound API (cpaDcLZ4SCompressBound()) is intended to return the maximum size of the output buffer. However, this API is not returning the correct value, which can lead to a lz4s buffer overflow. |
| Implication | Applications may experience buffer overflows even when using the output of compressBound API to allocate output buffers. |
| Resolution | Fixed in 23.11 |
| Affected OS | Linux |
| Driver/Module | QAT IA - Compression |

## QATE-93278
| Title      |         GEN - sample_code potential seg-fault, issue #46     |
|----------|:-------------
| Reference # | QATE-93278 |
| Description | cpa_dc_stateless_multi_op_checksum_sample.c missed checking the return value of a memory allocation. See [issue 46](https://github.com/intel/qatlib/issues/46). |
| Implication | In a low memory system, if the memory allocation fails, the process could crash. |
| Resolution | Fixed in qatlib 23.08. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-90845
| Title      |         GEN - QAT service fails to start, issue #38 |
|----------|:-------------
| Reference # | QATE-90845 |
| Description | QAT service fails to start. The qat service may fail if the kernel driver's initialization is not fully finished when the service starts. See [issue 38](https://github.com/intel/qatlib/issues/38). |
| Implication | The qatmgr may not detect any or all of the vfio devices. |
| Resolution | Fixed in 23.08. The service waits until the kernel driver has completed initialization of all PFs before starting the service. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-78459
| Title      |         DC - cpaDcDeflateCompressBound API returns incorrect output buffer size when input size exceeds 477218588 bytes.     |
|----------|:-------------
| Reference # | QATE-74786 |
| Description | When cpaDcDeflateCompressBound API is called with input size > 477218588 bytes incorrect buffer size is returned. For any buffer input size, the API should not produce output buffer size greater than the max limit (4 GB).   |
| Implication | Incorrect output buffer size is returned instead of error. |
| Resolution | The issue is not present in qatlib. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - Data Compression |

## QATE-76846
| Title      |         GEN - Forking and re-initializing use-cases do not work     |
|----------|:-------------
| Reference # | QATE-76846 |
| Description | Forking and re-initializing use-cases do not work:<br>-icp_sal_userStart()/icp_sal_userStop()/icp_sal_userStart() in single process<br>-icp_sal_userStart()/fork()/icp_sal_userStart() in child.<br> This is the use case in openssh + QAT_Engine. |
| Implication | The process will have undefined behavior in these use-cases. |
| Resolution | Fixed in 21.08. If using release prior to this release and using these flows, call qaeMemDestroy() immediately after icp_sal_userStop() to prevent this issue. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## QATE-12241
| Title      |         CY - TLS1.2 with secret key lengths greater than 64 are not supported     |
|----------|:-------------
| Reference # | QATE-12241 |
| Description | Algorithms, as with Diffie-Hellman using 8K parameters that can use a secret key length greater than 64 bytes is not supported.|
| Implication | Key generation would fail for TLS1.2 algorithms that use more than 64 bytes secret length keys. |
| Resolution | Fixed in 22.07. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - Crypto |

 ## Licensing
* This product is released under the BSD-3-Clause.

## Legal

Intel, Intel Atom, and Xeon are trademarks of
Intel Corporation in the U.S. and/or other countries.

\*Other names and brands may be claimed as the property of others.

Copyright &copy; 2016-2022, Intel Corporation. All rights reserved.

## Terminology

| Term   |      Description      |
|----------|:-------------:|
| API | Application Programming Interface |
| BIOS | Basic Input/Output System |
| BSD | Berkeley Standard Distribution |
| CY | Cryptographic |
| CnV | Compress and Verify |
| CnVnR | Compress and Verify and Recover |
| DC | Compression |
| DMA | Direct Memory Access |
| EFI | Extensible Firmware Interface |
| FW | Firmware |
| GPL | General Public License |
| HKDF | HMAC-based Extract-and-Expand Key Derivation Function |
| Intel® QAT | Intel® QuickAssist Technology |
| OS | Operating System |
| SR-IOV | Single-root Input/Output Virtualization |
| TLS | Transport Layer Security |
| VFs | Virtual Functions |

