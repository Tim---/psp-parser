#!/usr/bin/env python3

from structures import PspType, BiosType
from termcolor import colored


class ParserException(Exception):
    pass


class Node(object):
    def __init__(self):
        self.children = None
        self.signature_status = None
        self.encryption_status = None
        self.parsing_status = None
        self.version = None
        self.disk_data = None
        self.logs = []

    def pretty_print(self, key='', level=0):
        def translate(letter, status):
            if status is None:
                return ' '
            elif status is False:
                return '-'
            else:
                return colored(letter, status)

        pre = ' ' * 4 * level

        sign = translate('S', self.signature_status)
        enc = translate('E', self.encryption_status)
        parse = translate('P', self.parsing_status)
        ver = '' if self.version is None else f' (v{self.version})'

        print(f'{pre}{key.ljust(16)} {sign}{enc}{parse} {self!r}{ver}')

        for s in self.get_logs():
            print(pre + '  ' + s)

        if self.children:
            for k, n in self.children.items():
                n.pretty_print(k, level+1)

    def __repr__(self):
        return self.__class__.__name__

    def get_logs(self):
        colors = {'error': 'red', 'warning': 'yellow', 'info': 'white'}
        for tag, msg in self.logs:
            yield colored(f'{tag.capitalize()}: {msg}', colors[tag])

    def log(self, tag, msg):
        self.logs.append((tag, msg))

    def error(self, msg):
        self.log('error', msg)
        raise ParserException(msg)

    def warning(self, msg):
        self.log('warning', msg)

    def info(self, msg):
        self.log('info', msg)

    def dump_to_disk(self, path):
        if self.children is not None:
            # Assume that directories only have children data
            for k, c in self.children.items():
                c.dump_to_disk(path / str(k))
            return

        if self.disk_data is None:
            return

        path.parent.mkdir(exist_ok=True, parents=True)
        with path.open('wb') as ofd:
            ofd.write(self.disk_data)


class GenericEntry(Node):
    def parse(self, ctx, entry):
        self.addr = None
        self.size = None
        self.entry = entry
        return self


class GenericPspEntry(GenericEntry):
    def __repr__(self):
        if self.addr:
            extent = f'{self.addr:08x}:{self.addr+self.entry.size-1:08x}'
        else:
            extent = ' '*17
        if self.__class__.__name__ == 'GenericPspEntry':
            return f'{extent} {self.get_key()} (Generic)'
        else:
            return f'{extent} {self.get_key()}'

    def get_key(self):
        entry = self.entry
        if entry.type in PspType._value2member_map_:
            t = PspType._value2member_map_[entry.type].name
        else:
            t = f'UNKNOWN_{entry.type:02x}'
        return f'{t}-{int(entry.subprog)}'


class GenericBiosEntry(GenericEntry):
    def __repr__(self):
        if self.addr:
            extent = f'{self.addr:08x}:{self.addr+self.entry.size-1:08x}'
        else:
            extent = ' '*17
        return f'{extent} {self.get_key()}'

    def get_key(self):
        entry = self.entry
        if entry.type in BiosType._value2member_map_:
            t = BiosType._value2member_map_[entry.type].name
        else:
            t = f'UNKNOWN_{entry.type:02x}'
        return f'{t}-{int(entry.subprog)}-{int(entry.flags.inst)}'


class MemoryPspEntry(GenericPspEntry):
    def parse(self, ctx, entry):
        super().parse(ctx, entry)
        self.addr = ctx.convert_addr(entry.addr)
        self.size = entry.size
        data = ctx.get_bytes(self.addr, self.size)
        try:
            self.parse_data(ctx, data)
        except ParserException:
            pass
        return self

    def parse_data(self, ctx, data):
        raise NotImplementedError()


class MemoryBiosEntry(GenericBiosEntry):
    def parse(self, ctx, entry):
        super().parse(ctx, entry)
        self.addr = ctx.convert_addr(entry.source)
        self.size = entry.size
        data = ctx.get_bytes(self.addr, self.size)
        try:
            self.parse_data(ctx, data)
        except ParserException:
            pass
        return self

    def parse_data(self, ctx, data):
        raise NotImplementedError()
