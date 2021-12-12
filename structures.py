#!/usr/bin/env python3

from construct import *
import enum


u8 = Hex(Int8ul)
u16 = Hex(Int16ul)
u32 = Hex(Int32ul)
u64 = Hex(Int64ul)

EMBEDDED_FIRMWARE_OFFSETS = (0xfffa0000, 0xfff20000, 0xffe20000, 0xffc20000, 0xff820000, 0xff020000)

# https://github.com/coreboot/coreboot/blob/master/util/amdfwtool/amdfwtool.c
embedded_firmware_t = Struct(
    'signature' / Const(0x55aa55aa, u32),
    'imc_entry' / u32,
    'gec_entry' / u32,
    'xhci_entry' / u32,
    'psp_entry' / u32,
    'comboable' / u32,
    'bios0_entry' / u32,
    'bios1_entry' / u32,
    'bios2_entry' / u32,
    'efs_gen' / u32,
    'bios3_entry' / u32,
    'rsvd_2Ch' / u32,
    'promontory_fw_ptr' / u32,
    'lp_promontory_fw_ptr' / u32,
    'reserved_38h' / u32,
    'reserved_3Ch' / u32,
    'spi_readmode_f15_mod_60_6f' / u8,
    'fast_speed_new_f15_mod_60_6f' / u8,
    'reserved_42h' / u8,
    'spi_readmode_f17_mod_00_2f' / u8,
    'spi_fastspeed_f17_mod_00_2f' / u8,
    'qpr_dummy_cycle_f17_mod_00_2f' / u8,
    'reserved_46h' / u8,
    'spi_readmode_f17_mod_30_3f' / u8,
    'spi_fastspeed_f17_mod_30_3f' / u8,
    'micron_detect_f17_mod_30_3f' / u8,
    'reserved_4Ah' / u8,
    'reserved_4Bh' / u8,
    'reserved_4Ch' / u32,
)

psp_directory_header_t = Struct(
    'cookie' / OneOf(Bytes(4), [b'$PSP', b'$PL2']),
    'checksum' / u32,
    'num_entries' / Rebuild(u32, len_(this._.entries)),
    'additional_info' / u32,
)

psp_directory_entry_t = Struct(
    'type' / u8,
    'subprog' / u8,
    'rsvd' / u16,
    'size' / u32,
    'addr' / u64, # In some entries, this is not a pointer
)

psp_directory_table_t = Struct(
    'header' / psp_directory_header_t,
    'entries' / psp_directory_entry_t[this.header.num_entries],
)

psp_combo_header_t = Struct(
    'cookie' / Const(b'2PSP', Bytes(4)),
    'checksum' / u32,
    'num_entries' / u32,
    'lookup' / u32,
    'reserved' / Const(0, u64)[2],
)

psp_combo_entry_t = Struct(
    'id_sel' / u32, # 0 -Compare PSP ID, 1 -Compare chip family ID
    'id' / u32,
    'lvl2_addr' / u64,
)

psp_combo_table_t = Struct(
    'header' / psp_combo_header_t,
    'entries' / psp_combo_entry_t[this.header.num_entries],
)


bios_combo_header_t = Struct(
    'cookie' / Const(b'2BHD', Bytes(4)),
    'checksum' / u32,
    'num_entries' / u32,
    'lookup' / u32,
    'reserved' / Const(0, u64)[2],
)

bios_combo_entry_t = Struct(
    'id_sel' / u32, # 0 -Compare PSP ID, 1 -Compare chip family ID
    'id' / u32,
    'lvl2_addr' / u64,
)
bios_combo_table_t = Struct(
    'header' / bios_combo_header_t,
    'entries' / bios_combo_entry_t[this.header.num_entries],
)


class PspType(enum.IntEnum):
    FW_PSP_PUBKEY         =  0x00
    FW_PSP_BOOTLOADER     =  0x01
    FW_PSP_SECURED_OS     =  0x02
    FW_PSP_RECOVERY       =  0x03
    FW_PSP_NVRAM          =  0x04
    FW_PSP_RTM_PUBKEY     =  0x05
    FW_PSP_SMU_FIRMWARE   =  0x08
    FW_PSP_SECURED_DEBUG  =  0x09
    PSP_FUSE_CHAIN        =  0x0b
    FW_PSP_TRUSTLETS      =  0x0c
    FW_PSP_TRUSTLETKEY    =  0x0d
    FW_PSP_SMU_FIRMWARE2  =  0x12
    DEBUG_UNLOCK          =  0x13
    HW_IPCFG              =  0x20
    WRAPPED_IKEK          =  0x21
    TOKEN_UNLOCK          =  0x22
    SEC_GASKET            =  0x24
    MP2_FW                =  0x25
    DRIVER_ENTRIES        =  0x28
    FW_KVM_IMAGE          =  0x29
    S0I3_DRIVER           =  0x2d
    ABL0                  =  0x30
    ABL1                  =  0x31
    ABL2                  =  0x32
    ABL3                  =  0x33
    ABL4                  =  0x34
    ABL5                  =  0x35
    ABL6                  =  0x36
    ABL7                  =  0x37
    FW_PSP_WHITELIST      =  0x3a
    VBIOS_BTLOADER        =  0x3c
    FW_L2_PTR             =  0x40
    FW_USB_PHY            =  0x44
    FW_TOS_SEC_POLICY     =  0x45
    FW_DRTM_TA            =  0x47
    FW_KEYDB_BL           =  0x50
    FW_KEYDB_TOS          =  0x51
    FW_PSP_VERSTAGE       =  0x52
    FW_VERSTAGE_SIG       =  0x53
    RPMC_NVRAM            =  0x54
    FW_DMCU_ERAM          =  0x58
    FW_DMCU_ISR           =  0x59
    FW_PSP_SMUSCS         =  0x5f
    FW_PSP_BOOTLOADER_AB  =  0x73

    # Guessed types
    AGESA_PUBKEY          =  0x0a  # Signed public key (AGESA ?)
    SIGNED_KEY_43         =  0x43  # Signed public key
    SIGNED_KEY_4E         =  0x4e  # Signed public key
    FW_L2_PTR_48          =  0x48  # PSP L2 table with relative addresses
    FW_L2_PTR_4A          =  0x4a  # PSP L2 table with relative addresses
    BIOS_L2_PTR_49        =  0x49  # BIOS L2 table with relative addresses
    X86_STUB_06           =  0x06  # X86 stub, no FW header
    FW_10                 =  0x10  # Some firmware, with FW header
    FW_14                 =  0x14  # Some firmware, with FW header
    FW_2A                 =  0x2a  # Some firmware, with FW header
    FW_42                 =  0x42  # Some firmware, with FW header
    FW_55                 =  0x55  # Some firmware, with FW header
    EMPTY_1A              =  0x1a  # All 0xff
    FW_SIGNATURE_2B       =  0x2b  # Another embedded firmware signature or the same ?

    UNK_07                =  0x07
    UNK_2E                =  0x2e
    UNK_2F                =  0x2f
    UNK_46                =  0x46
    SECURITY_GASKET_APP   =  0x4c
    UNK_4D                =  0x4d




dst64 = Hex(ExprAdapter(u64, lambda obj, ctx: obj if obj != 0xffffffff_ffffffff else None, None))

bios_directory_header_t = Struct(
    'cookie' / OneOf(Bytes(4), [b'$BHD',  b'$BL2']),
    'checksum' / u32,
    'num_entries' / u32,
    'additional_info' / u32,
)

bios_directory_entry_t = Struct(
    'type' / u8,
    'region_type' / u8,
    #'flags' / u8,
    'flags' / BitStruct(
        'inst' / Nibble,
        'compressed' / Bit,
        'ro' / Bit,
        'copy' / Bit,
        'reset' / Bit,
    ),
    'subprog' / u8,
    'size' / u32,
    'source' / u64,
    'dest' / u64,
)

bios_directory_table_t = Struct(
    'header' / bios_directory_header_t,
    'entries' / bios_directory_entry_t[this.header.num_entries],
)

class BiosType(enum.IntEnum):
    RTM_PUBKEY      =  0x05
    APCB            =  0x60
    APOB            =  0x61
    BIN             =  0x62
    APOB_NV         =  0x63
    PMUI            =  0x64
    PMUD            =  0x65
    UCODE           =  0x66
    APCB_BK         =  0x68
    MP2_CFG         =  0x6a
    PSP_SHARED_MEM  =  0x6b
    L2_PTR          =  0x70

    # Guessed types
    UNK_67           =  0x67


# PSP types

key_usage_t = Enum(u32,
    AMD_ROOT_SIGNING_KEY=0x00,
    AMD_AGESA_SIGNING_KEY=0x02, # guessed
    AMD_SEV_SIGNING_KEY=0x13
)

pubkey_t = Struct(
    'version' / Const(1, u32),
    'key_id' / Hex(Bytes(16)),
    'certifying_id' / Hex(Bytes(16)),
    'key_usage' / key_usage_t,
    'reserved' / Const(bytes(16), Bytes(16)),
    'pubexp_size' / OneOf(u32, (0x800, 0x1000)),
    'modulus_size' / OneOf(u32, (0x800, 0x1000)),
    'pubexp' / BytesInteger(this.pubexp_size // 8, swapped=True),
    'modulus' / BytesInteger(this.modulus_size // 8, swapped=True),
)

pubkey_signed_t = Struct(
    'pubkey' / RawCopy(pubkey_t),
    #'signature' / Bytes(this.pubkey.value.modulus_size // 8), # Probably wrong, it should be the size of the signing pubkey
    'signature' / GreedyBytes,
)


# The original
fw_header_t = Struct(
    'a' / Bytes(0x10),

    'magic' / Bytes(4),
    'size_signed' / u32,
    'encrypted' / u32,
    'b' / u32,

    'iv' / Bytes(0x10),
    
    'signed' / u32,
    'c' / u32,
    'certifying_id' / Bytes(0x10),
    'compressed' / u32,
    'd' / u32,
    'size_uncompressed' / u32,
    'zlib_size' / u32,
    'e' / u32,
    'f' / u32,
    'version' / u32,
    'g' / u32,
    'load_addr' / u32,
    'rom_size' / u32,
    'h' / u32,
    'i' / u32,
    'has_intermediate_key' / u32,
    'j' / u32,
    'wrapped_key' / Bytes(0x10),
    'rest' / Bytes(112),
    Terminated,
)

bool_t = OneOf(u32, [0, 1])
tern_t = OneOf(u32, [0, 1, 2])

maybe_const = lambda n, t: t

fw_header_t = Struct(
    'a' / Bytes(0x10),

    'magic' / Bytes(4),
    'size_signed' / u32,
    'encrypted' / bool_t,
    '_b' / maybe_const(0, u32),

    'iv' / Bytes(0x10),
    
    'signed' / bool_t,
    'c' / tern_t,
    'certifying_id' / Bytes(0x10),
    'compressed' / bool_t,
    'd' / tern_t,
    'size_uncompressed' / u32,
    'zlib_size' / u32,
    'e' / u32,
    '_f' / maybe_const(0, u32),
    'version' / Bytes(4),
    'g' / u32,
    'load_addr' / u32,
    'rom_size' / u32,
    '_h' / maybe_const(0, u32),
    'i' / u32,
    'has_intermediate_key' / bool_t,
    'j' / u32, # Similar to PspType
    'wrapped_key' / Bytes(0x10),
    '_p' / maybe_const(0, u32)[4],

    'k' / u32, # 100% agesa specific
    'l' / u32,
    'm' / u32,
    '_o' / maybe_const(0, u32),

    '_q' / maybe_const(0, u32)[8],
    'n' / Bytes(32),
    '_r' / maybe_const(0, u32)[4],
    Terminated,
)


kdb_item_t = Prefixed(u32,
    Struct(
        'version' / Const(1, u32),
        'n' / u32, # Not unique !
        'pubexp' / u32,
        'key_id' / Bytes(16),
        'modulus_size' / u32, # Or maybe 0x30 bytes exponent ?
        Const(bytes(0x2c)),
        'modulus' / BytesInteger(this.modulus_size // 8, swapped=True),
        Terminated,
    ),
    includelength=True
)

kdb_inner_t = Struct(
    'version' / Const(1, u32),
    'signature' / Const(b'$KDB'),
    Const(bytes(68)),
    'entries' / GreedyRange(kdb_item_t),
    Terminated,
)

kdb_t = FocusedSeq('data',
    'data' / Prefixed(u32, kdb_inner_t, includelength=True),
    Terminated,
)



def Range(size, subcon):
    return FixedSized(size, FocusedSeq('data',
        'data' / GreedyRange(subcon),
        Terminated,
    ))


type_t = Struct(
    '_group_id' / u16,
    Check(this._group_id == this._._.group_id),
    'type_id' / u16,
    '_size' / u16,
    '_other_id' / Const(0, u16),
    '_pad' / Const(bytes(8)),
    'data' / Bytes(this._size - 0x10),
)

group_t = Struct(
    'magic' / Bytes(4),
    'group_id' / u16,
    '_a' / Const(0x10, u16),
    '_b' / Const(0x1, u16),
    '_c' / Const(0x0, u16),
    '_size' / u32,
    'types' / Range(this._size - 0x10, type_t),
)

apcb_t = Struct(
    'magic' / Const(b'APCB \0 \0'),
    '_size' / u32,
    'a' / u32,
    #'_b' / Const(bytes(0x10)),
    'b' / Bytes(0x10),
    'groups' / Range(this._size - 0x20, group_t),
)

apcb_simple_t = Struct(
    'magic' / Bytes(8),
    '_size' / u32,
    'a' / u32,
    'b' / Bytes(0x10),
    'data' / Bytes(this._size - 0x20),
)

