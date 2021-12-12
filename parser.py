#!/usr/bin/env python3

import pathlib
from structures import u32, EMBEDDED_FIRMWARE_OFFSETS, PspType, BiosType
from construct import Pointer, Bytes
import logging
import coloredlogs
from collections import OrderedDict
import os
from contextlib import contextmanager
from nodes import EmbeddedFirmware, PSP_HANDLER, MAGIC_HANDLER, BIOS_HANDLER
import argparse

logger = logging.getLogger('parser')
coloredlogs.install(fmt='%(name)s %(levelname)s %(message)s', level=logging.INFO)


class Context(object):
    def __init__(self, fd):
        self.fd = fd

        # Compute the base address of the ROM
        file_size = os.fstat(fd.fileno()).st_size
        assert file_size in (0x2000000, 0x1000000, 0x800000)
        self.base = 0x100000000 - min(0x1000000, file_size)
        self.convert_addr = self.address_converter_generic

        # Reset key material
        self.signing_keys = {}
        self.enc_key = None

    def read(self, offset, size):
        self.fd.seek(offset)
        return self.fd.read(size)

    def parse_struct(self, offset, st):
        return Pointer(offset, st).parse_stream(self.fd)

    def get_bytes(self, offset, size):
        return self.parse_struct(offset, Bytes(size))
        # return Pointer(offset, Bytes(size)).parse_stream(self.fd)

    def decrypt(self, data, wrapped_key, iv):
        if not self.enc_key:
            return None
        return self.enc_key.decrypt(data, wrapped_key, iv)

    def address_converter_generic(self, addr):
        # Assume that these values are bad
        if addr in [0x00000000, 0xffffffff, 0x00ffffff]:
            return None

        # Maybe the addresses are relative to 0, maybe they are relative to self.base
        high = addr >> 24
        assert high in (0x00, 0xff)
        if high == 0:
            return addr
        else:
            return addr - self.base

    def address_converter_relative(self, base):
        def converter(addr):
            if addr & 0x8000_0000_0000_0000:
                return base + (addr & 0x7fff_ffff_ffff_ffff)
            else:
                return addr
        return converter

    @contextmanager
    def change_address_converter(self, converter):
        old = self.convert_addr
        self.convert_addr = converter
        try:
            yield
        finally:
            self.convert_addr = old

    def parse_psp_entries(self, entries):
        # Reset IKEK
        self.enc_key = None

        first = [
            PspType.FW_PSP_PUBKEY,
            PspType.FW_PSP_RTM_PUBKEY,
            PspType.FW_PSP_TRUSTLETKEY,
            PspType.AGESA_PUBKEY,
            PspType.SIGNED_KEY_43,
            PspType.SIGNED_KEY_4E,
            PspType.FW_KEYDB_BL,
            PspType.FW_KEYDB_TOS,
            PspType.WRAPPED_IKEK,
            PspType.FW_PSP_BOOTLOADER,
            PspType.FW_PSP_RECOVERY,
            PspType.DRIVER_ENTRIES,
        ]
        last = [
            PspType.FW_L2_PTR,
            PspType.FW_L2_PTR_48,
            PspType.FW_L2_PTR_4A,
            PspType.BIOS_L2_PTR_49,
        ]

        return self.parse_entries_by_priority(first, last, entries, self.parse_psp_entry)

    def parse_bios_entries(self, entries):
        first = [
            BiosType.RTM_PUBKEY
        ]
        last = [
            BiosType.L2_PTR
        ]

        return self.parse_entries_by_priority(first, last, entries, self.parse_bios_entry)

    def parse_psp_entry(self, entry):
        cls = PSP_HANDLER[entry.type]
        return cls().parse(self, entry)

    def parse_bios_entry(self, entry):
        cls = BIOS_HANDLER[entry.type]
        return cls().parse(self, entry)

    def parse_magic_entry(self, addr, allowed=set()):
        tr_addr = self.convert_addr(addr)
        if tr_addr is None:
            return
        magic = self.parse_struct(tr_addr, Bytes(4))
        if magic not in allowed:
            #logger.warning(f'Unallowed magic {magic} at addr {tr_addr:08x}')
            return
        cls = MAGIC_HANDLER[magic]
        return cls().parse(self, tr_addr)

    def parse_entries_by_priority(self, first, last, entries, parser):
        '''
        Entries in a directory are not parsed in the order they appear.
        We must first parse the crypto (public keys, ikek) entries, and then the rest.
        '''
        other = list(sorted(set(range(256)) - set(first) - set(last)))

        # Maps each type to a priority
        prio = {t: p for p, t in enumerate(first + other + last)}

        # Entries, sorted by priority
        sorted_entries = sorted(enumerate(entries), key=lambda tup: prio[tup[1].type])

        # We parse each entries
        parsed_entries = [(i, parser(entry)) for i, entry in sorted_entries]

        res = OrderedDict()
        for i, entry in sorted(parsed_entries):
            key = entry.get_key()
            assert key not in res  # Check that keys are unique
            res[key] = entry
        return res


def parse_firmware(fd):
    ctx = Context(fd)
    for addr in EMBEDDED_FIRMWARE_OFFSETS:
        addr = ctx.convert_addr(addr)
        o = ctx.parse_struct(addr, u32)
        if o == 0x55aa55aa:
            return EmbeddedFirmware().parse(ctx, addr)
    else:
        raise Exception('No embedded firmware !')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=argparse.FileType('rb'))
    args = parser.parse_args()

    o = parse_firmware(args.file)
    o.pretty_print()
    o.dump_to_disk(pathlib.Path(args.file.name).with_suffix('.out'))


if __name__ == "__main__":
    main()
