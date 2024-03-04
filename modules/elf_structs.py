'''Basic module defining ELF structures and constants'''
from enum import Enum
from construct import Struct, Int16ul, Int16ub, \
Int32ul, Int32ub, Int64ul, Int64ub, Bytes, IfThenElse, If

class ElfConstants(Enum):
    '''ENUM Class for certain ELF constants'''
    ELF32_SIZE   = 52
    ELF64_SIZE   = 64
    ELFCLASS_IDX = 4
    ELFDATA_IDX  = 5
    ELFCLASS32   = 1
    ELFCLASS64   = 2
    ELFLE        = 1
    ELFBE        = 2
    ELFPH32_SIZE = 32
    ELFPH64_SIZE = 56

PT_TYPE_DICT = {
    'PT_NULL':	    0,
    'PT_LOAD':	    1,
    'PT_DYNAMIC':	2,
    'PT_INTERP':	3,
    'PT_NOTE':	    4,
    'PT_SHLIB':	    5,
    'PT_PHDR':	    6,
    'PT_TLS':	    7,
    'PT_LOOS':	    0x60000000,
    'PT_HIOS':	    0x6fffffff,
    'PT_LOPROC':	0x70000000,
    'PT_HIPROC':	0x7fffff
}

def __elf_header(elf_int16, elf_int32, elf_int64, is_64):
    entry_off = IfThenElse(is_64, elf_int64, elf_int32)
    return Struct(
        "e_ident"       / Bytes(16),
        "e_type"        / elf_int16,
        "e_machine"     / elf_int16,
        "e_version"     / elf_int32,
        "e_entry"       / entry_off,
        "e_phoff"       / entry_off,
        "e_shoff"       / entry_off,
        "e_flags"       / elf_int32,
        "e_ehsize"      / elf_int16,
        "e_phentsize"   / elf_int16,
        "e_phnum"       / elf_int16,
        "e_shentsize"   / elf_int16,
        "e_shnum"       / elf_int16,
        "e_shstrndx"    / elf_int16,
        )

def elf_header(is_le=True, is_64=False):
    '''ELF header structure'''
    if is_le:
        return __elf_header(Int16ul, Int32ul, Int64ul, is_64=is_64)
    return __elf_header(Int16ub, Int32ub, Int64ub, is_64=is_64)

def __elf_prog_header(elf_int32, elf_int64, is_64):
    elf_addr = IfThenElse(is_64, elf_int64, elf_int32)
    return Struct(
        "type"      / elf_int32,
        "flags_64"  / If(is_64, elf_int32),
        "offset"    / elf_addr,
        "vaddr"     / elf_addr,
        "paddr"     / elf_addr,
        "filesz"    / elf_addr,
        "memsz"     / elf_addr,
        "flags_32"  / If((not is_64), elf_int32),
        "align"     / elf_addr,
    )

def elf_prog_header(is_le=True, is_64=False):
    '''Program header structure'''
    if is_le:
        return __elf_prog_header(Int32ul, Int64ul, is_64=is_64)
    return __elf_prog_header(Int32ub, Int64ub, is_64=is_64)
