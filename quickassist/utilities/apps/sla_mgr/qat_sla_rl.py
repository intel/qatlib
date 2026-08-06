#!/usr/bin/env python3
#*****************************************************************************
#
#   SPDX-License-Identifier: BSD-3-Clause
#   Copyright(c) 2007-2026 Intel Corporation
# 
#   These contents may have been developed with support from one or more
#   Intel-operated generative artificial intelligence solutions.
#
#*****************************************************************************/
#
# qat_sla_rl.py - underlying implementation used by qat_sla_mgr.
#
# This script can be invoked directly for advanced use cases, but is not a
# supported interface and may change without notice.  Run ./qat_sla_rl.py --help for
# usage details.
#
# By default, values are in the device's internal permille units (0-1000,
# representing a fraction of the device's maximum capacity).  Use the
# --scale_mbps (-sm) flag to specify CIR and PIR in Mbps instead.
#

import os
import re
from argparse import ArgumentParser, HelpFormatter
import textwrap

# DBDF format: domain is optional (e.g. both "BB:DD.F" and "DDDD:BB:DD.F" are valid)
dbdf_regex = r"^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$"
rl_ops = ["add", "update", "rm", "rm_all", "list", "caps", "cap_rem", "get"]
rl_services = ["asym", "sym", "dc", "decomp", "dcc"]
# Service capacity in Mbps, keyed by PCI device ID
# Maximum SLA ID to scan (mirrors ADF_MAX_SLA in SAL C code)
MAX_SLA_ID = 64
# Service capacity in Mbps, keyed by PCI device ID
DEVICE_CAPS = {
    "0x4940": {"asym": 173750, "sym": 95000, "dc": 45000, "dcc": 45000},
    "0x4942": {"asym": 173750, "sym": 95000, "dc": 45000, "dcc": 45000},
    "0x4944": {"asym": 173750, "sym": 95000, "dc": 45000, "dcc": 45000},
    "0x4946": {"asym": 173750, "sym": 95000, "dc": 45000, "dcc": 45000},
    "0x4948": {"asym": 173750, "sym": 95000, "dc": 40000, "decomp": 40000, "dcc": 40000},
}
ophelp = f'''
Rate Limiting configuration tool

Supported operations:

Create SLA using RPs mask \t ./%(prog)s add\t <pf_addr> -c <cir> -p <pir> -s <service> -r <ring pairs mask>
Create SLA using VF addr \t ./%(prog)s add\t <vf_addr> -c <cir> -p <pir> -s <service>
Update SLA \t\t\t ./%(prog)s update\t <pf_addr> -i <sla_id> -c <cir> -p <pir>
Get SLA \t\t\t ./%(prog)s get\t <pf_addr> -i <sla_id>
Delete SLA \t\t\t ./%(prog)s rm\t <pf_addr> -i <sla_id>
Delete all SLAs \t\t ./%(prog)s rm_all\t <pf_addr>
List all SLAs \t\t ./%(prog)s list\t <pf_addr>
Remaining service capacity \t ./%(prog)s cap_rem <pf_addr> -s <service>
All service capacity \t\t ./%(prog)s caps\t <pf_addr>

CIR and PIR values must be positive values.


'''

class RawFormatter(HelpFormatter):
    def _fill_text(self, text, width, indent):
        text = textwrap.dedent(text)
        text = textwrap.indent(text, indent)
        text = text.splitlines()
        text = [textwrap.fill(line, width) for line in text]
        text = "\n".join(text)
        return text

class Ratelimiting:
    def resolve_pf_dbdf(self, dbdf):
        dev_path = f"/sys/bus/pci/devices/{dbdf}"
        physfn = os.path.join(dev_path, "physfn")

        if os.path.islink(physfn):
            # VF → PF
            pf_path = os.readlink(physfn)
            return os.path.basename(pf_path)

        return dbdf

    def __init__(self, dbdf, operation, sla_id, cir, pir, service, rp, scale):
        if not re.match(dbdf_regex, dbdf):
            raise Exception("Incorrect BDF format: " + dbdf + ". Expected format: [DDDD:]BB:DD.F (e.g. 0000:05:00.0 or 05:00.0)")
        if not dbdf.count(':') == 2:
            dbdf = "0000:" + dbdf

        self.dbdf = dbdf
        match = re.split(r"[:\.]", dbdf)
        self.bdf_bus = match[1]
        self.bdf_dev = match[2]
        self.bdf_func = match[3]

        self.input_dbdf = self.dbdf
        self.pf_dbdf = self.resolve_pf_dbdf(self.dbdf)

        self.sysfs_dir = os.path.join("/sys/bus/pci/devices", self.pf_dbdf)
        self.qat_rl_dir = os.path.join(self.sysfs_dir, "qat_rl")

        if not os.path.exists(os.path.join(self.sysfs_dir, "qat")):
            raise Exception(f"QAT device with address: `{dbdf}` does not exist")

        self.operation_file = os.path.join(self.qat_rl_dir, "sla_op")
        if not os.path.exists(self.operation_file):
            raise Exception(f"QAT device with address: `{dbdf}` does not support Rate Limiting")

        pci_device_id_file = os.path.join(self.sysfs_dir, "device")
        with open(pci_device_id_file, "r") as f:
            self.pci_device_id = f.read().strip()

        self.operation = operation
        self.cir = cir
        self.pir = pir
        self.srv = service
        self.sla_id = sla_id
        self.rp = int(rp, 0) if rp else 0
        self.scale = scale


    def add(self):
        if self.srv == "":
            raise Exception("Service type is required for add operation. Use -s <service>")
        if self.rp == 0:
            if self.input_dbdf == self.pf_dbdf:
                raise Exception("Ring Pair Mask not provided. Use -r or provide a VF address")
            if not self.is_sriov_enabled():
                raise Exception("Ring Pair Mask not provided and SR-IOV is not enabled")
            print("Ring Pair Mask not provided, trying to calculate it from VF address.")
            self.rp = self.set_rp_mask_from_vf()
        if self.cir <= 0:
            raise Exception("CIR value must be greater than 0")
        if self.pir < self.cir:
            print("PIR must be >= CIR, setting PIR to CIR value")
            self.pir = self.cir

        if self.scale:
            s_cir = self.scale_to_permille(int(self.cir))
            s_pir = self.scale_to_permille(int(self.pir))
            self.set("cir", s_cir)
            self.set("pir", s_pir)
        else:
            self.set("cir", self.cir)
            self.set("pir", self.pir)
        try:
            self.set("srv", self.srv)
        except OSError as error:
            if error.errno == 22:
                raise Exception(f"Service '{self.srv}' is not enabled on this PF")
            raise
        self.set("rp", self.rp)
        self._write_op(self.operation)
        print("SLA ID:", self.get("id"))

    def update(self):
        if self.cir <= 0:
            raise Exception("CIR value must be greater than 0")
        self.set("id", self.sla_id)
        self._write_op("get")
        if self.scale:
            self.srv = self.get("srv")
        if self.pir == 0:
            self.pir = int(self.get("pir"))
            if self.scale:
                self.pir = self.scale_to_mbps(self.pir)
        if self.pir < self.cir:
            print("PIR must be >= CIR, setting PIR to CIR value")
            self.pir = self.cir
        if self.scale:
            s_cir = self.scale_to_permille(int(self.cir))
            s_pir = self.scale_to_permille(int(self.pir))
            self.set("cir", s_cir)
            self.set("pir", s_pir)
        else:
            self.set("cir", self.cir)
            self.set("pir", self.pir)
        self._write_op(self.operation)

    def get_sla(self):
        self.set("id", self.sla_id)
        self._write_op("get")
        print("\n\tSLA ID:", self.get("id"))
        cir = self.get("cir")
        pir = self.get("pir")
        self.srv = self.get("srv")
        if self.scale:
            cir = str(self.scale_to_mbps(int(cir)))
            pir = str(self.scale_to_mbps(int(pir)))
        print("\tCIR:", cir)
        print("\tPIR:", pir)
        print("\tSRV:", self.srv)
        rp = self.get("rp")
        print("\tRP:", rp)
        if self.is_sriov_enabled():
            vf_addr = self.rp_mask_to_vf_addr(rp)
            if vf_addr:
                print("\tVF:", vf_addr)

    def rm(self):
        self.set("id", self.sla_id)
        self._write_op(self.operation)

    def rm_all(self):
        self._write_op(self.operation)

    def get_configured_services(self):
        """Read rp2srv sysfs to discover which services are configured on this PF."""
        qat_rp2srv = os.path.join(self.sysfs_dir, "qat/rp2srv")
        services = set()
        for i in range(4):
            try:
                with open(qat_rp2srv, "w") as file:
                    file.write(str(i))
                with open(qat_rp2srv, "r") as file:
                    srv = file.read().strip()
                    if srv in rl_services:
                        services.add(srv)
            except OSError as error:
                if error.errno == 22:
                    # Ring pair not configured or invalid index (EINVAL)
                    print(f"Ring pair {i} not configured (errno: {error.errno})")
                    continue
                # Raise unexpected errors (e.g., permission issues, missing sysfs node)
                raise Exception(f"Unexpected OSError for ring pair {i}: errno={error.errno}, {error.strerror}")
        return services

    def cap_rem(self):
        if self.srv == "":
            raise Exception("Service type is required for cap_rem operation. Use -s <service>")
        cap_rem_file = os.path.join(self.sysfs_dir, "qat_rl/cap_rem")
        try:
            self.set("cap_rem", self.srv)
            with open(cap_rem_file, "r") as file:
                val = file.read().strip()
                if self.scale:
                    val = self.scale_to_mbps(int(val))
        except OSError as error:
            if error.errno == 22:
                raise Exception(f"Service '{self.srv}' is not enabled on this PF")
            raise
        if self.scale:
            max_mbps = self.get_max_mbps()
            print("Remaining capacity for \'{}\' is: {} of: {}".format(self.srv, val, max_mbps))
        else:
            print("Remaining capacity for \'{}\' is: {}".format(self.srv, val))

    def caps(self):
        errors = []
        for srv in sorted(self.get_configured_services()):
            self.srv = srv
            try:
                self.cap_rem()
            except Exception as e:
                print(f"Error querying service '{srv}': {e}")
                errors.append(srv)
        if errors:
            raise Exception(f"Failed to query capacity for: {', '.join(errors)}")

    def set(self, f, value):
        set_file = os.path.join(self.sysfs_dir, "qat_rl/" + f)
        try:
            with open(set_file, "w") as file:
                file.write(str(value))
        except OSError as e:
            raise OSError(e.errno, f"Error writing to {f}: {e.strerror}", set_file) from e

    def get(self, f):
        set_file = os.path.join(self.sysfs_dir, "qat_rl/" + f)
        try:
            with open(set_file, "r") as file:
                return file.read().strip()
        except OSError as e:
            raise OSError(e.errno, f"Error reading from {f}: {e.strerror}", set_file) from e

    def _write_op(self, op):
        with open(self.operation_file, "w") as file:
            file.write(op)

    def list(self):
        print("Listing SLAs for device:", self.dbdf)
        print("--------------------------------------------------")
        found = False
        for sla_id in range(0, MAX_SLA_ID):
            try:
                self.sla_id = sla_id
                self.get_sla()
            except OSError as error:
                if error.errno == 22:
                    continue
                raise

            found = True

        if not found:
            print("No SLAs configured")

    def get_max_mbps(self):
        caps = DEVICE_CAPS.get(self.pci_device_id)
        if caps is None:
            raise Exception(f"No capacity data for device ID {self.pci_device_id}")
        if self.srv not in caps:
            raise Exception(f"Unknown service type: '{self.srv}'")
        return caps[self.srv]

    def scale_to_mbps(self, rate: int):
        max_mbps = self.get_max_mbps()
        val = int(rate * max_mbps / 1000)
        if val == 0 and rate > 0:
            val = 1
        return val

    def scale_to_permille(self, rate: int):
        max_mbps = self.get_max_mbps()
        val = int(rate * 1000 / max_mbps)
        if val == 0 and rate > 0:
            val = 1
        return val

    def set_rp_mask_from_vf(self):
        # bdf_dev and bdf_func are hexadecimal components of the PCI BDF
        dev = int(self.bdf_dev, 16)
        func = int(self.bdf_func, 16)
        vf_id = (dev * 8 + func - 1)
        if vf_id not in range(0,16):
            raise Exception("Mask calculation failed: VF addr: {} does not exist in QAT".format(self.dbdf))
        rp_mask = hex(self.get_srv2rp_mask() << (vf_id *4))
        return rp_mask

    def is_sriov_enabled(self):
        numvfs_file = os.path.join(self.sysfs_dir, "sriov_numvfs")
        try:
            with open(numvfs_file, "r") as f:
                return int(f.read().strip()) > 0
        except (OSError, ValueError):
            return False

    def rp_mask_to_vf_addr(self, rp_mask_str):
        """Translate RP mask back to VF address. Returns None if not possible."""
        try:
            rp_mask = int(rp_mask_str, 0)
            if rp_mask == 0:
                return None
            # Find the lowest non-zero nibble to determine vf_id
            vf_id = 0
            temp = rp_mask
            while temp & 0xF == 0:
                temp >>= 4
                vf_id += 1
            if vf_id not in range(0, 16):
                return None
            # vf_id = dev * 8 + func - 1
            pci_id = vf_id + 1
            dev = pci_id // 8
            func = pci_id % 8
            pf_match = re.split(r"[:\.]", self.pf_dbdf)
            domain = pf_match[0]
            bus = pf_match[1]
            return f"{domain}:{bus}:{dev:02x}.{func}"
        except (ValueError, IndexError):
            return None

    def get_srv2rp_mask(self):
        qat = os.path.join(self.sysfs_dir, "qat/rp2srv")
        mask = 0
        for i in range(4):
            try:
                with open(qat, "w") as file:
                    file.write(str(i))
                with open(qat, "rt") as file:
                    srv = file.read().strip()
                    if srv == self.srv:
                        mask = mask | (1 << i)
            except OSError as error:
                if error.errno == 22:
                    # Ring pair not configured or invalid index (EINVAL)
                    print(f"Ring pair {i} not configured (errno: {error.errno})")
                    continue
                # Raise unexpected errors (e.g., permission issues, missing sysfs node)
                raise Exception(f"Unexpected OSError for ring pair {i}: errno={error.errno}, {error.strerror}")
        if mask == 0:
            raise Exception("No ring pairs assigned to service {} on this PF".format(self.srv))
        return mask

# Main function.
if __name__ == "__main__":
    parser = ArgumentParser(description=ophelp, formatter_class=RawFormatter)

    parserg1 = parser.add_argument_group(title='Parameters', description='Arguments needed for operations')
    parserg1.add_argument('operation', action='store',  choices=rl_ops, help='Operation to perform',
                                metavar="operation")
    parserg1.add_argument('bdf', action='store', help='[Domain] Bus Device Function address - XX:XX.X', metavar="pci_bdf")
    parserg1.add_argument("--cir", "-c", action='store', dest='cir',
                                help='Committed information rate', default=0,
                                type=int, metavar="N")
    parserg1.add_argument('--pir',  '-p', action='store', dest='pir',
                                help='Peak information rate' , default=0,
                                type=int, metavar="N")
    parserg1.add_argument('--sla_id',  '-i', action='store', dest='sla_id',
                                help='SLA identification', default=0,
                                type=int, metavar="N")
    parserg1.add_argument('--service',  '-s', action='store', dest='service',
                                help='SLA service type', default="", metavar="srv",
                                choices=rl_services)
    parserg1.add_argument('--ring_pairs',  '-r', action='store', dest='ring_pairs',
                                help='Ring pair hexadecimal mask (max 64bit)', default="",
                                type=str, metavar="0xNN")
    parserg2 = parser.add_argument_group(title='Misc', description='Additional arguments')
    parserg2.add_argument('--scale_mbps',  '-sm', action='store_true', dest='scale',
                                help='Scale to old Mbps units', default=False)

    args = parser.parse_args()

    # Run the command
    try:
        rl = Ratelimiting(args.bdf, args.operation, args.sla_id, args.cir, args.pir, args.service, args.ring_pairs, args.scale)
        FUNC_MAP = {
            "add": rl.add,
            "update": rl.update,
            "get": rl.get_sla,
            "rm": rl.rm,
            "rm_all": rl.rm_all,
            "cap_rem": rl.cap_rem,
            "caps": rl.caps,
            "list": rl.list,
        }

        func = FUNC_MAP[args.operation]
        func()
    except OSError as error:
        print('Operation `' + args.operation + '` failed with: ' + str(error) + '\nCheck kernel log for more details.')
        exit(1)
    except Exception as error:
        print('Operation `' + args.operation + '` failed with: ' + str(error))
        exit(1)

    exit(0)
