#!/usr/bin/env python3

from structures import bios_directory_table_t, BiosType, pubkey_t, apcb_t, pubkey_signed_t, fw_header_t, apcb_simple_t
from basenodes import MemoryBiosEntry, GenericBiosEntry
from pspcrypto import SignKey
from collections import defaultdict
from construct import FocusedSeq, Terminated
import zlib

BIOS_HANDLER = defaultdict(lambda: GenericBiosEntry)


def bios_entry(type_):
    def wrapper(cls):
        BIOS_HANDLER[type_] = cls
        return cls
    return wrapper


@bios_entry(BiosType.UNK_67)
@bios_entry(BiosType.APOB_NV)
class EmptyEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        if data.rstrip(b'\xff'):
            self.warning('not empty')
            self.disk_data = data
        else:
            self.info('empty')


@bios_entry(BiosType.APOB)
class ApobEntry(GenericBiosEntry):
    def parse(self, ctx, entry):
        super().parse(ctx, entry)
        assert entry.size == 0
        assert entry.source == 0
        self.info(f'Apob address: {entry.dest:08x}')
        return self


@bios_entry(BiosType.APCB)
@bios_entry(BiosType.APCB_BK)
class ApcbEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        o = apcb_simple_t.parse(data)
        if data[o._size:].rstrip(b'\xff'):
            self.warning('Data after apcb')
        self.disk_data = data[:o._size]


@bios_entry(BiosType.BIN)
class BinEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        # Contains an UEFI image with PEI modules
        self.disk_data = data


@bios_entry(BiosType.UCODE)
class UcodeEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        self.disk_data = data


@bios_entry(BiosType.PMUI)
@bios_entry(BiosType.PMUD)
class PmudEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        # self.info('todo')
        # print(data)
        # self.disk_data = data
        o = fw_header_t.parse(data[:0x100])
        assert o.a == bytes(16)
        assert o.magic == b'\x05\x00\x00\x00'
        assert o.encrypted == 0
        assert o.iv == bytes(16)
        assert o.signed == 1
        assert o.c == 0
        assert o.compressed == 1
        assert o.d == 0
        assert o.g == 0xffffffff
        assert o.load_addr == 0x100
        assert o.i == 0
        assert o.has_intermediate_key == 0
        assert o.wrapped_key == bytes(16)
        assert o.m == 0

        # assert o.size_signed == 0
        # assert o.version == b'\x01\x00\x00\x00'
        # assert o.j == 0
        # assert o.k == 0
        # assert o.l == 0
        if o.version == b'\x01\x00\x00\x00':
            assert o.size_signed == 0
            assert o.j == 0
            assert o.k == 0
            assert o.l == 0
        else:
            return self.error('TODO: check signature for these firmwares')

        # Not true for some motherboards
        # assert o.n == bytes(32)
        # assert o.e == 0

        assert len(data) == o.rom_size

        header, data = data[:0x100], data[0x100:]

        rounded_zlib_size = o.zlib_size + (- o.zlib_size % 0x10)
        compressed_data, padding, signature_data = data[:o.zlib_size], data[o.zlib_size:rounded_zlib_size], data[rounded_zlib_size:]
        assert not padding.rstrip(b'\x00')

        decompressed_data = zlib.decompress(compressed_data)
        assert len(decompressed_data) == o.size_uncompressed

        signer = ctx.signing_keys.get(o.certifying_id)
        self.info(f'Certifying id: {o.certifying_id.hex()}')

        verif = signer.verify(header, signature_data)  # TODO: if size_signed is 0, we only verify the header !
        if not verif:
            return self.error('Could not verify signature')
        else:
            self.warning('Only the header is signed !')
        self.disk_data = decompressed_data


@bios_entry(BiosType.RTM_PUBKEY)
class BiosPubkeyEntry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        o = FocusedSeq('data', 'data' / pubkey_signed_t, Terminated).parse(data)

        self.info(f'Key id: {o.pubkey.value.key_id.hex()}')
        self.info(f'Certifying id: {o.pubkey.value.certifying_id.hex()}')

        signer = ctx.signing_keys.get(o.pubkey.value.certifying_id)
        # assert signer
        if not signer:
            return self.error('Unknown signer !')
        assert signer.verify(o.pubkey.data, o.signature[::-1])
        self.signature_status = 'green'

        self.pub = SignKey.build(o.pubkey.value)
        self.key_id = o.pubkey.value.key_id
        ctx.signing_keys[o.pubkey.value.key_id] = self.pub
        self.encryption_status = False
        self.parsing_status = 'green'


@bios_entry(BiosType.L2_PTR)
class BiosL2Entry(MemoryBiosEntry):
    def parse_data(self, ctx, data):
        st = bios_directory_table_t.parse(data)

        self.children = ctx.parse_bios_entries(st.entries)

        return self
