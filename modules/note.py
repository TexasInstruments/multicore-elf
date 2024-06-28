'''Module which defines the note segment for the multicore elf'''

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.abspath(os.path.dirname(__file__)), "../pkgs")))

from enum import Enum
from construct import Struct, Int32ul, Int32ub, Int64ul, Int64ub, \
    Array, IfThenElse, Padding, Byte, Bytes, If

class NoteTypes(Enum):
    '''Enum subclass defining the different note types'''
    VENDOR_ID = 0xAAAA5555
    SEGMENT_MAP = 0xBBBB7777
    ENTRY_POINTS = 0xCCCC9999
    CUSTOM = 0xDEADC0DE

class CustomNote():
    '''Helper class to build custom notes'''
    def __init__(self, name, data) -> None:
        self.name = name
        self.data = data

def get_ep_format(islittle: bool, is64: bool):
    '''Function to return the entry point format'''
    uint32_t = IfThenElse(islittle, Int32ul, Int32ub)
    uint64_t = IfThenElse(islittle, Int64ul, Int64ub)
    entrypoint = IfThenElse(is64, uint64_t, uint32_t)

    return Struct(
        "core_id" / uint32_t,
        "entry_point" / entrypoint
    )

def get_note_format(islittle: bool, name: str, descsz: int, itemtype=Byte):
    '''Function to return the basic note format'''
    uint32_t = IfThenElse(islittle, Int32ul, Int32ub)
    namelen = len(name)
    padname = 0
    paddesc = 0
    alignsize = 4
    if namelen % alignsize != 0:
        padname = alignsize - (namelen % alignsize)
    if descsz % alignsize != 0:
        paddesc = alignsize - (descsz % alignsize)
    return Struct(
        "namesz" / uint32_t,
        "descsz" / uint32_t,
        "type" / uint32_t,
        "name" / Bytes(namelen),
        Padding(padname),
        "desc" / If((descsz != 0), Array(int(descsz / itemtype.sizeof()), itemtype)),
        Padding(paddesc)
    )

def get_note_vendor(islittle):
    '''Function to return the vendor ID note'''
    name = "Texas Instruments "
    note_format = get_note_format(islittle, name, 0)
    dummy_data = bytearray(note_format.sizeof())
    note = note_format.parse(dummy_data)
    note.namesz = len(name)
    note.descsz = 0
    note.type   = NoteTypes.VENDOR_ID.value
    note.name   = bytes(name.encode('ascii'))
    note_data   = note_format.build(note)
    return bytearray(note_data)


def get_note_segment_map(islittle, seglist):
    '''Function to return the segment map note'''
    name = "Segment Map "
    desclen = len(seglist)
    note_format = get_note_format(islittle, name, desclen)
    dummy_data = bytearray(note_format.sizeof())
    note = note_format.parse(dummy_data)
    note.namesz = len(name)
    note.descsz = desclen
    note.type   = NoteTypes.SEGMENT_MAP.value
    note.name   = bytes(name.encode('ascii'))
    note.desc   = seglist
    note_data   = note_format.build(note)
    return bytearray(note_data)

def __ep_serialize(islittle: bool, is64: bool, eplist: dict):
    ser_list = []
    for coreid, e_entry in eplist.items():
        itemtype = get_ep_format(islittle, is64)
        dummy_data = bytearray(itemtype.sizeof())
        ep_note = itemtype.parse(dummy_data)
        ep_note.core_id = int(coreid)
        ep_note.entry_point = e_entry
        ser_list.append(ep_note)
    return ser_list

def get_note_entrypoints(islittle, is64, eplist):
    '''Function to return the segment map note'''
    name = "Entry Points "
    itemtype = get_ep_format(islittle, is64)
    itemsize = itemtype.sizeof()
    desclen = len(eplist) * itemsize
    note_format = get_note_format(islittle, name, desclen, itemtype=itemtype)
    dummy_data = bytearray(note_format.sizeof())
    note = note_format.parse(dummy_data)
    note.namesz = len(name)
    note.descsz = desclen
    note.type   = NoteTypes.ENTRY_POINTS.value
    note.name   = bytes(name.encode('ascii'))
    note.desc   = __ep_serialize(islittle, is64, eplist)
    note_data   = note_format.build(note)
    return bytearray(note_data)

def get_note_custom(islittle, cust: CustomNote):
    '''Function to return custom note with descriptor as serialized data (byte array)'''
    desclen = len(cust.data)
    name = cust.name
    note_format = get_note_format(islittle, f'{name} ', desclen)
    dummy_data = bytearray(note_format.sizeof())
    note = note_format.parse(dummy_data)
    note.namesz = len(name)
    note.descsz = desclen
    note.type   = NoteTypes.CUSTOM.value
    note.name   = bytes(name.encode('ascii'))
    note.desc   = cust.data
    note_data   = note_format.build(note)
    return bytearray(note_data)

if __name__ == "__main__":
    # This is a module
    pass
