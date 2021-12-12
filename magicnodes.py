#!/usr/bin/env python3

from structures import (
    embedded_firmware_t, psp_directory_table_t, psp_combo_table_t,
    bios_directory_table_t, bios_combo_table_t
)
from collections import OrderedDict
from basenodes import Node


MAGIC_HANDLER = {}


def magic_entry(type_):
    def wrapper(cls):
        MAGIC_HANDLER[type_] = cls
        return cls
    return wrapper


class GenericDirectory(Node):
    def parse(self, ctx, addr):
        st = ctx.parse_struct(addr, self.directory_struct)

        self.children = self.parse_entries(ctx, st.entries)

        return self


@magic_entry(b'$PSP')
class PspDirectory(GenericDirectory):
    directory_struct = psp_directory_table_t

    def parse_entries(self, ctx, entries):
        return ctx.parse_psp_entries(entries)


@magic_entry(b'$BHD')
class BiosDirectory(GenericDirectory):
    directory_struct = bios_directory_table_t

    def parse_entries(self, ctx, entries):
        return ctx.parse_bios_entries(entries)


class GenericCombo(Node):
    def parse(self, ctx, addr):
        st = ctx.parse_struct(addr, self.struct)
        self.children = OrderedDict()
        for i, entry in enumerate(st.entries):
            id_sel = ['PSP', 'CHIP'][entry.id_sel]
            selector = f'{id_sel}-{entry.id:08x}'

            res = ctx.parse_magic_entry(entry.lvl2_addr, allowed=self.allowed)
            if res:
                self.children[selector] = res

        return self


@magic_entry(b'2PSP')
class PspCombo(GenericCombo):
    struct = psp_combo_table_t
    allowed = {b'$PSP'}


@magic_entry(b'2BHD')
class BiosCombo(GenericCombo):
    struct = bios_combo_table_t
    allowed = {b'$BHD'}


class EmbeddedPsp(Node):
    def parse(self, ctx, st):
        self.children = OrderedDict()
        psp_entries = [st.psp_entry, st.comboable]
        for i, addr in enumerate(psp_entries):
            res = ctx.parse_magic_entry(addr, allowed={b'$PSP', b'2PSP'})
            if res:
                self.children[f'psp{i}'] = res

        return self


class EmbeddedBios(Node):
    def parse(self, ctx, st):
        self.children = OrderedDict()
        bios_entries = [
            st.bios0_entry, st.bios1_entry,
            st.bios2_entry, st.bios3_entry
        ]
        for i, addr in enumerate(bios_entries):
            res = ctx.parse_magic_entry(addr, allowed={b'$BHD', b'2BHD'})
            if res:
                self.children[f'bios{i}'] = res

        return self


class EmbeddedFirmware(Node):
    def parse(self, ctx, addr):
        st = ctx.parse_struct(addr, embedded_firmware_t)

        self.children = OrderedDict()
        self.children['psp'] = EmbeddedPsp().parse(ctx, st)
        self.children['bios'] = EmbeddedBios().parse(ctx, st)

        return self
