<!--   SPDX-License-Identifier: BSD-3-Clause -->
<!--   Copyright(c) 2007-2026 Intel Corporation -->
<!--  -->
<!--   These contents may have been developed with support from one or more -->
<!--   Intel-operated generative artificial intelligence solutions. -->

# QAT Rate Limiting Configuration Tools

The QAT in-tree driver implements rate limiting configuration via the [sysfs interface](https://docs.kernel.org/admin-guide/abi-testing-files.html#abi-file-testing-sysfs-driver-qat-rl). This utility provides command-line wrappers built on top of that sysfs layer. For full documentation on QAT rate limiting, see the [Programmer's Guide](https://intel.github.io/quickassist/PG/infrastructure_ratelimiting.html).

## qat_sla_mgr

`qat_sla_mgr` is the supported command-line interface for managing rate limiting Service Level Agreements (SLAs). It requires root access and operates on PF and host-side VF addresses (VFs passed through to a guest are not supported). All throughput values (CIR, PIR) are expressed in **Mbps**. Both `qat_sla_mgr` and `qat_sla_rl.py` must reside in the same directory.

**CIR** (Committed Information Rate) is the guaranteed minimum throughput for an SLA. **PIR** (Peak Information Rate) is the maximum allowed throughput. PIR must be greater than or equal to CIR. Both values must be positive.

> **Note:** The device operates internally in permille units (0–1000) representing a fraction of the service's maximum capacity. CIR and PIR values specified in Mbps are converted to this internal scale and may be rounded down to the nearest supported granularity. As a result, the effective values reported by `list` or `get` may be lower than what was requested. The granularity depends on the device and service type — for example, a service with a 45000 Mbps maximum has a step size of 45 Mbps.

**Usage**

| Operation | Command |
| --------- | ------- |
| Create SLA | `./qat_sla_mgr create <vf_addr> <cir> <pir> <service>` |

The `create` command assigns an SLA covering all ring-pairs of the given service type on the specified VF. If you need an SLA that spans multiple VFs, or separate SLAs on individual ring-pairs within a VF, use `qat_sla_rl.py` or the sysfs interface directly.

The `create` command prints the assigned SLA ID on success. Use this ID with the PF address for subsequent `update` and `delete` operations. SLAs are managed at the PF level — the VF address is only needed at creation time to derive the ring-pair mask.

| Update SLA | `./qat_sla_mgr update <pf_addr> <sla_id> <cir> <pir>` |
| Delete SLA | `./qat_sla_mgr delete <pf_addr> <sla_id>` |
| Delete all SLAs | `./qat_sla_mgr delete_all <pf_addr>` |
| List all SLAs | `./qat_sla_mgr list <pf_addr>` |
| Device capacity | `./qat_sla_mgr caps <pf_addr>` |

**Output details**

- **create**: prints the assigned SLA ID.
- **update**: no output on success.
- **delete / delete_all**: no output on success.
- **list**: prints all configured SLAs with their ID, CIR, PIR (in Mbps), service type, ring-pair mask, and VF address (if SR-IOV is enabled). SLAs created directly via the sysfs interface are included, but the displayed VF address is derived from the ring-pair mask and may be incomplete for SLAs that span multiple VFs.
- **caps**: prints the maximum and remaining capacity (in Mbps) for every service configured on the device.
