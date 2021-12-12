#!/usr/bin/env python3

from structures import (
    psp_directory_table_t, PspType, bios_directory_table_t, pubkey_t,
    pubkey_signed_t, fw_header_t, kdb_t
)
from construct import Pointer, FocusedSeq, Terminated
import zlib
import yara
from basenodes import MemoryPspEntry, GenericPspEntry
from pspcrypto import SignKey, CryptKey
from collections import defaultdict

PSP_HANDLER = defaultdict(lambda: GenericPspEntry)


def psp_entry(type_):
    def wrapper(cls):
        PSP_HANDLER[type_] = cls
        return cls
    return wrapper


class TestEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        self.disk_data = data


@psp_entry(PspType.FW_PSP_SMUSCS)
class SmuScsEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        # Some other SMU firmware ?
        self.disk_data = data


@psp_entry(PspType.X86_STUB_06)
class X86StubEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        # it looks like there is a ELF-like header at the start.
        self.disk_data = data


@psp_entry(PspType.FW_KVM_IMAGE)
@psp_entry(PspType.UNK_07)
@psp_entry(PspType.EMPTY_1A)
@psp_entry(PspType.FW_PSP_NVRAM)
@psp_entry(PspType.TOKEN_UNLOCK)
class EmptyEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        # All 0xff
        if data.rstrip(b'\xff'):
            self.warning('Not empty')
            self.disk_data = data
        else:
            self.info('Empty')


@psp_entry(PspType.PSP_FUSE_CHAIN)
class FuseChainEntry(GenericPspEntry):
    def parse(self, ctx, entry):
        super().parse(ctx, entry)
        assert entry.size == 0xffffffff
        # data = entry.addr
        return self


@psp_entry(PspType.FW_PSP_PUBKEY)
class PubkeyEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        o = pubkey_t.parse(data)

        assert o.key_id == o.certifying_id
        self.info(f'Key id: {o.key_id.hex()}')
        self.signature_status = 'green' # We don't know the public AMD keys, any self-signed is good :)

        self.pub = SignKey.build(o)
        ctx.signing_keys[o.key_id] = self.pub

        ctx.root_key_id = o.key_id

        self.encryption_status = False
        self.parsing_status = 'green'


@psp_entry(PspType.FW_PSP_RTM_PUBKEY)
@psp_entry(PspType.FW_PSP_SECURED_DEBUG)
@psp_entry(PspType.FW_PSP_TRUSTLETKEY)
@psp_entry(PspType.AGESA_PUBKEY)
@psp_entry(PspType.SIGNED_KEY_43)
@psp_entry(PspType.SIGNED_KEY_4E)
class SignedPubkeyEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        o = FocusedSeq('data', 'data' / pubkey_signed_t, Terminated).parse(data)

        self.info(f'Key id: {o.pubkey.value.key_id.hex()}')
        self.info(f'Certifying id: {o.pubkey.value.certifying_id.hex()}')

        signer = ctx.signing_keys.get(o.pubkey.value.certifying_id)
        if not signer:
            return self.error('Unknown signer !')
        assert signer.verify(o.pubkey.data, o.signature[::-1])
        self.signature_status = 'green'

        self.pub = SignKey.build(o.pubkey.value)
        self.key_id = o.pubkey.value.key_id
        ctx.signing_keys[o.pubkey.value.key_id] = self.pub
        self.encryption_status = False
        self.parsing_status = 'green'


@psp_entry(PspType.WRAPPED_IKEK)
class IkekEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        key = CryptKey.build(data)
        ctx.enc_key = key
        if not key:
            self.error(f'Unknown wrapped ikek ({data.hex()})')
        else:
            self.info(f'Wrapped ikek ({data.hex()})')
        self.encryption_status = 'green' if key else 'red'
        self.signature_status = False
        self.parsing_status = 'green'


@psp_entry(PspType.FW_L2_PTR)
class PspL2Entry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        st = psp_directory_table_t.parse(data)

        self.children = ctx.parse_psp_entries(st.entries)

        self.encryption_status = False
        self.signature_status = False
        self.parsing_status = 'green'
        return self


@psp_entry(PspType.FW_L2_PTR_48)
@psp_entry(PspType.FW_L2_PTR_4A)
class PspExtL2Entry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        st = psp_directory_table_t.parse(data)

        with ctx.change_address_converter(ctx.address_converter_relative(self.addr)):
            self.children = ctx.parse_psp_entries(st.entries)

        self.encryption_status = False
        self.signature_status = False
        self.parsing_status = 'green'
        return self


@psp_entry(PspType.BIOS_L2_PTR_49)
class PspExtL2BiosEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        st = bios_directory_table_t.parse(data)

        with ctx.change_address_converter(ctx.address_converter_relative(self.addr)):
            self.children = ctx.parse_bios_entries(st.entries)

        self.encryption_status = False
        self.signature_status = False
        self.parsing_status = 'green'
        return self


@psp_entry(PspType.UNK_46)  # once again, "encrypted" is not valid and looks like an address
@psp_entry(PspType.FW_PSP_SECURED_OS)  # seems special. o.encrypted is often invalid ?
@psp_entry(PspType.S0I3_DRIVER)  # Sometimes all 0xff ?
class BrokenFwPspEntry(MemoryPspEntry):
    def parse_data(self, ctx, data):
        pass  # TODO
        self.disk_data = data


@psp_entry(PspType.FW_PSP_BOOTLOADER)
@psp_entry(PspType.FW_PSP_RECOVERY)
@psp_entry(PspType.FW_PSP_SMU_FIRMWARE)
@psp_entry(PspType.FW_PSP_TRUSTLETS)
@psp_entry(PspType.FW_PSP_SMU_FIRMWARE2)
@psp_entry(PspType.DEBUG_UNLOCK)
@psp_entry(PspType.SEC_GASKET)
@psp_entry(PspType.MP2_FW)
@psp_entry(PspType.DRIVER_ENTRIES)
@psp_entry(PspType.ABL0)
@psp_entry(PspType.ABL1)
@psp_entry(PspType.ABL2)
@psp_entry(PspType.ABL3)
@psp_entry(PspType.ABL4)
@psp_entry(PspType.ABL5)
@psp_entry(PspType.ABL6)
@psp_entry(PspType.ABL7)
@psp_entry(PspType.FW_USB_PHY)  # Guessing
@psp_entry(PspType.FW_10)
@psp_entry(PspType.FW_14)
@psp_entry(PspType.FW_2A)
@psp_entry(PspType.FW_42)
@psp_entry(PspType.FW_55)
@psp_entry(PspType.UNK_2E)
@psp_entry(PspType.UNK_2F)
@psp_entry(PspType.SECURITY_GASKET_APP)
@psp_entry(PspType.UNK_4D)
@psp_entry(PspType.HW_IPCFG)
@psp_entry(PspType.VBIOS_BTLOADER)
@psp_entry(PspType.FW_TOS_SEC_POLICY)
@psp_entry(PspType.FW_DRTM_TA)
@psp_entry(PspType.FW_DMCU_ERAM)
@psp_entry(PspType.FW_DMCU_ISR)
class FwPspEntry(MemoryPspEntry):
    def parse_data_legacy(self, ctx, data):
        self.info('Legacy header')
        o = fw_header_t.parse(data[:0x100])
        header, data = data[:0x100], data[0x100:]

        assert o.encrypted == 0
        assert o.iv == bytes(16)
        assert o.c == 0
        assert o.d == 0
        assert o.zlib_size == 0
        assert o.e == 0
        assert o.rom_size == 0
        assert o.i == 0
        assert o.has_intermediate_key == 0
        assert o.wrapped_key == bytes(16)
        assert o.k == 0
        assert o.l == 0
        assert o.m == 0
        assert o.n == bytes(32)

        if o.compressed:
            self.info('compressed')
            data, rest = data[:o.size_signed], data[o.size_signed:]
            assert not rest.rstrip(b'\xff')
            uncompressed = zlib.decompress(data)
            if o.signed:
                data, signature_data = uncompressed[:-0x100], uncompressed[-0x100:]
                signer = ctx.signing_keys.get(o.certifying_id)
                assert signer.verify(data, signature_data[::-1]) # header not signed
                self.disk_data = header + data
                self.signature_status = 'green'
                self.parsing_status = 'green'
            else:
                if self.entry.type in (PspType.FW_PSP_SMU_FIRMWARE, PspType.FW_PSP_SMU_FIRMWARE2):
                    data, signature_data = uncompressed[:-0x100], uncompressed[-0x100:]
                    key_id = ctx.root_key_id
                    signer = ctx.signing_keys.get(key_id)
                    assert signer.verify(data, signature_data[::-1])
                    self.disk_data = header + data
                    self.signature_status = 'green'
                    self.parsing_status = 'green'
                else:
                    self.signature_status = 'red'
                    return self.error('Unsigned')
        else:
            data, rest = data[:o.size_signed], data[o.size_signed:]
            if o.signed:
                signature_data, rest = rest[:0x100], rest[0x100:]
                assert not rest.rstrip(b'\xff')
                signer = ctx.signing_keys.get(o.certifying_id)
                assert signer.verify(header + data, signature_data[::-1])
                self.disk_data = header + data
                self.signature_status = 'green'
                self.parsing_status = 'green'
            else:
                self.signature_status = 'red'
                return self.error('Not signed')

    def get_comp_ratio(self, data):
        return len(zlib.compress(data)) / len(data)

    def decompress(self, o, data):
        assert o.zlib_size

        rounded_zlib_size = o.zlib_size + (- o.zlib_size % 0x10) # We add to align to 16 bytes

        # Split the compressed data and signature
        compressed_data = data[:o.zlib_size]
        pad = data[o.zlib_size:rounded_zlib_size]
        signature_data = data[rounded_zlib_size:]

        # Check that padding is padding
        assert not set(pad) - {0}

        # Decompress and check size
        uncompressed_data = zlib.decompress(compressed_data)
        assert len(uncompressed_data) == o.size_uncompressed

        if o.size_uncompressed != o.size_signed:
            # Is size_signed != 0, it seems to be ok
            self.warning(f"Size uncompressed ({hex(o.size_uncompressed)}) != size signed ({hex(o.size_signed)})")
            unsigned_data = uncompressed_data[o.size_signed:]
            uncompressed_data = uncompressed_data[:o.size_signed]
        else:
            unsigned_data = b''

        data = uncompressed_data

        return data, unsigned_data, signature_data

    def decrypt(self, ctx, o, data):
        comp_ratio = self.get_comp_ratio(data)
        if comp_ratio < .95:
            self.warning(f'Data entropy before encryption looks small (comp_ratio = {comp_ratio})')

        data = ctx.decrypt(data, o.wrapped_key, o.iv)
        if not data:
            self.error("Unknown encryption key")
            return

        comp_ratio = self.get_comp_ratio(data)
        if comp_ratio > .95:
            self.warning(f'Data entropy after encryption looks big (comp_ratio = {comp_ratio})')
            self.encryption_status = 'yellow'
        else:
            self.encryption_status = 'green'

        return data

    def get_signer(self, ctx, o, signature_data):
        if o.has_intermediate_key:
            assert len(signature_data) == 0x440  # Or not !

            # Parse signature and intermediate key
            signature_data, intermediate_data = signature_data[:0x100], signature_data[0x100:]
            signed_interm_key = pubkey_signed_t.parse(intermediate_data)

            self.info(f'Intermediate key id: {signed_interm_key.pubkey.value.key_id.hex()}')
            self.info(f'Intermediate certifying id: {signed_interm_key.pubkey.value.certifying_id.hex()}')

            # Verify intermediate key
            signer = ctx.signing_keys.get(signed_interm_key.pubkey.value.certifying_id)
            assert signer.verify(signed_interm_key.pubkey.data, signed_interm_key.signature[::-1])

            assert o.certifying_id, signed_interm_key.pubkey.value.key_id

            # Create the intermediate key
            signer = SignKey.build(signed_interm_key.pubkey.value)
            assert signer
        else:
            self.info(f'Certifying id: {o.certifying_id.hex()}')
            signer = ctx.signing_keys.get(o.certifying_id)

        return signature_data, signer

    def parse_data(self, ctx, data):
        self.parsing_status = 'red'

        assert len(data) >= 0x100
        o = fw_header_t.parse(data[:0x100])

        self.version = '.'.join(map('{:02x}'.format, bytes(o.version)[::-1]))

        # First, let's mark if the fw is signed or encrypted
        assert o.signed in (0, 1)
        self.signature_status = 'red' if o.signed else False
        assert o.encrypted in (0, 1)
        self.encryption_status = 'red' if o.encrypted else False

        if not o.rom_size:
            return self.parse_data_legacy(ctx, data)

        if o.magic in (b'\x00\x00\x00\x00', b'\x01\x00\x00\x00'):
            self.warning('weird magic, maybe legacy')

        # Not legacy firmwares are always signed
        assert o.signed

        if len(data) != o.rom_size:
            self.warning(f"Data size ({hex(len(data))}) != ROM size ({hex(o.rom_size)})")
            data = data[:o.rom_size]  # TODO: do we miss some data ?

        # So, first, we can remove the header
        header, data = data[:0x100], data[0x100:]

        # probably not so special, but unseen yet
        assert not (o.compressed and o.encrypted)

        if o.compressed:
            data, unsigned_data, signature_data = self.decompress(o, data)
        else:
            data, signature_data = data[:o.size_signed], data[o.size_signed:]
            unsigned_data = b''

            assert o.zlib_size == 0
            assert o.size_uncompressed == 0 or o.size_uncompressed == len(data)

        if o.encrypted:
            data = self.decrypt(ctx, o, data)

        comp_ratio = self.get_comp_ratio(data + unsigned_data)
        if comp_ratio > .95:
            self.warning(f'Data entropy before signature looks high')

        signature_data, signer = self.get_signer(ctx, o, signature_data)

        if signer:
            if signer.verify(header + data, signature_data):
                self.signature_status = 'green'
            else:
                return self.error(f"Computed signature is invalid")
        else:
            self.parsing_status = 'yellow'
            return self.error(f"Unknown signing key ({o.certifying_id.hex()})")

        self.parsing_status = 'green'

        self.find_hardcoded_keys(ctx, data)

        self.parse_fw(ctx, data)

        self.disk_data = header + data

        if unsigned_data:
            self.disk_data += unsigned_data

    def parse_fw(self, ctx, data):
        return

    def get_data(self):
        return self.disk_data

    def find_hardcoded_keys(self, ctx, data):
        rules = yara.compile(source='''
        rule amdkey {
            strings:
                $key = { 01 00 00 00  [36]  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ( 00 08 00 00 | 00 10 00 00) ( 00 08 00 00 | 00 10 00 00 ) }
            condition:
                $key
        }
        ''')

        def cb(res):
            for offset, match, string in res['strings']:
                o = Pointer(offset, pubkey_t).parse(data)
                assert o.version == 1
                assert o.reserved == bytes(0x10)
                assert o.pubexp_size == o.modulus_size
                assert o.pubexp == 0x10001
                self.info(f'Found hardcoded key {bytes(o.key_id).hex()}')
                pub = SignKey.build(o)
                ctx.signing_keys[o.key_id] = pub

            return yara.CALLBACK_CONTINUE
        rules.match(data=data, callback=cb)


@psp_entry(PspType.FW_KEYDB_BL)
@psp_entry(PspType.FW_KEYDB_TOS)
class KdbEntry(FwPspEntry):
    def parse_fw(self, ctx, data):
        o = kdb_t.parse(data)
        for item in o.entries:
            key = SignKey.build(item)
            ctx.signing_keys[item.key_id] = key
