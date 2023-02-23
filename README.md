![Linux build with gcc](https://github.com/intel/qatlib/actions/workflows/linux_build_gcc.yml/badge.svg)
![CodeQL scan](https://github.com/intel/qatlib/actions/workflows/codeql.yml/badge.svg)

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
| February 2023 | 009 | 23.02 | - Added configuration option --enable-legacy-algorithms to use these insecure crypto algorithms and disabled them by default (AES-ECB, SHA-1, SHA2-224, SHA3-224, RSA512/1024/1536, DSA)<br>- Refactored code in quickassist/utilities/libusdm_drv<br>- Bugfixes<br>- Updated documentation with configuration and tuning information |
| November 2022 | 008 | 22.07.2 | - Changed from yasm to nasm for assembly compilation<br> - Added configuration option to use C implementation of soft CRC implementation instead of asm<br>- Added support for pkg-config<br>- Added missing lock around accesses to some global data in qatmgr |
| October 2022 | 007 | 22.07.1 | - Fix for QATE-86605 |
| July 2022 | 006 | 22.07 | - Added support for lz4/lz4s compression algorithms<br>- Added support for Compression End-to-end (E2E) integrity check<br>- Added support for PKE generic point multiply<br>- Updated QAT APIs<br>- Enabled CPM2.0b<br>- Split rpm package |
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
    AES-XTS (no partials support), AES-GCM, AES-CCM (192/256)
  * Message digest/hash ([SHA1](#insecure-algorithms), SHA2 ([224](#insecure-algorithms)/256/384/512),
    SHA3 ([224](#insecure-algorithms)/256/384/512) (no partials support) and
    authentication (AES-CBC-MAC, AES-XCBC-MAC)
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
  * Diffie-Hellman (DH) key generation phase 1 and 2 up to 8192 bits
  * [RSA](#insecure-algorithms) key generation, encryption/decryption and digital signature
    generation/verification up to 8192 bits
  * [DSA](#insecure-algorithms) parameter generation and digital signature generation/verification
  * Elliptic Curve Cryptography: ECDSA, ECDHE, Edwards Montgomery curves
  * Generic point multiply
* Compression
  * Deflate
  * lz4/lz4s
  * Compress and Verify (CnV)
  * Compress and Verify and Recover (CnVnR)
  * End-to-end (E2E) integrity check

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

To enable these algorithms, use the following configuration option:
   * `--enable-legacy-algorithms`

## Deprecated Features & Planned Deprecations
* The following configuration option will be deprecated after 2023:
  * `--enable-legacy-lib-names`

## Setup
Please refer to [INSTALL](INSTALL) for details on installing the library.

## Supported Devices
* 4xxx (QAT gen 4 devices)

Earlier generations of QAT devices (e.g. c62x, dh895xxcc, etc.) are not
supported.

## Limitations
* If an error occurs on the host driver (Heartbeat, Uncorrectable error) it
  will not be communicated to the library.

The following features are not currently supported:
* Dynamic instances
* Intel® Key Protection Technology (KPT)
* Event driven polling
* More than 16 processes per end point
* accumulateXXHash when combined with autoSelectBestHuffmanTree
* accumulateXXHash in Decompression or Combined sessions
* integrityCrcCheck for Compression direction requests


## Environmental Assumptions

The following assumptions are made concerning the deployment environment:
* Users within the same processing domain must be trusted.
* The Intel® QAT device should not be exposed (via the "user space direct"
  deployment model) to untrusted users.
* DRAM is considered to be inside the trust boundary. The typical memory
  protection schemes provided by the Intel architecture processor and memory
  controller, and by the operating system, prevent unauthorized access to these
  memory regions.
* A QuickAssist kernel driver for the supported device is installed, which has
  discovered and initialised the device, exposing the VFs. This driver is
  included in the Linux kernel, see [INSTALL](INSTALL) for information about which kernel 
  to use.
* The library can be used by unprivileged users if that user is included in
  the 'qat' group.

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
| QATE-76698 | [GEN- Multi-process applications running in guest will fail when running with default Policy settings.](#qate-76698) |

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
| Description | The default Policy setting results in process receiving all available VFs allocated to guest operating system. In the case of a multi-process application, failures will be observed as all available QAT resources are consumed by the first process. |
| Implication | Multi-process applications running in guest OS will fail with default Policy settings. |
| Resolution | When passing VFs to a guest, the libvirt XML file should specify that all VFs from a given PF (i.e. with the same host domain + bus) are assigned to a common bus on the guest. The first VF, mapped to function='0x0', should also set `multifunction='on'`. Also, if n processes are needed in the guest, then n VFs from each PF should be passed to the guest, to ensure all guest processes have both compression and crypto instances. In addition, on either host or guest, don’t use POLICY=1 as it will only allocate 1 instance. At least 2 instances are needed so a process has both CY and DC instances. Set either POLICY=0 or POLICY=2 (or 4, 6, ...) in `/etc/sysconfig/qat` and restart qatmgr. |
| Affected OS | Linux |
| Driver/Module | CPM-IA - General |

## Resolved Issues
Resolved issues relating to the Intel® QAT software are described
in this section.

| Issue ID | Description |
|-------------|------------|
| QATE-76846 | [GEN - Forking and re-initialising use-cases do not work](#qate-76846) |
| QATE-78459 | [DC - cpaDcDeflateCompressBound API returns incorrect output buffer size when input size exceeds 477218588 bytes.](#qate-74786) |
| QATE-12241 | [CY - TLS1.2 with secret key lengths greater than 64 are not supported.](#qate-12241) |

## QATE-76846
| Title      |         GEN - Forking and re-initialising use-cases do not work     |
|----------|:-------------
| Reference # | QATE-76846 |
| Description | Forking and re-initialising use-cases do not work:<br>-icp_sal_userStart()/icp_sal_userStop()/icp_sal_userStart() in single process<br>-icp_sal_userStart()/fork()/icp_sal_userStart() in child.<br> This is the usecase in openssh + QAT_Engine. |
| Implication | The process will have undefined behaviour in these use-cases. |
| Resolution | This issue is resolved with the 21.08 release. If using release prior to this release and using these flows, call qaeMemDestroy() immediately after icp_sal_userStop() to prevent this issue. |
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

## QATE-12241
| Title      |         CY - TLS1.2 with secret key lengths greater than 64 are not supported     |
|----------|:-------------
| Reference # | QATE-12241 |
| Description | Algorithms, as with Diffie-Hellman using 8K parameters that can use a secret key length greater than 64 bytes is not supported.|
| Implication | Key generation would fail for TLS1.2 algorithms that use more than 64 bytes secret length keys. |
| Resolution | This is resolved with the 22.07 release. |
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

