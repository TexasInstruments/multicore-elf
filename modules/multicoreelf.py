from elftools.elf.elffile import ELFFile, Segment
import os
import sys
sys.path.append(os.path.realpath('../'))
from modules import metadata
import struct

ELF_HEADER_SIZE = 52

class ELFHeader():
    def __init__(self, e_ident = bytearray(16), e_type = 0, e_machine = 0,
        e_version = 0, e_entry = 0, e_phoff = 0, e_shoff = 0, e_flags = 0,
        e_ehsize = 0, e_phentsize = 0, e_phnum = 0, e_shentsize = 0, e_shnum = 0,
        e_shstrndx = 0, le = True) -> None:
        self.e_ident = e_ident
        self.e_type = e_type
        self.e_machine = e_machine
        self.e_version = e_version
        self.e_entry = e_entry
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_flags = e_flags
        self.e_ehsize = e_ehsize
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx
        self.le = le

        if le:
            self.fmt = '<16s2H5I6H'
        else:
            self.fmt = '>16s2H5I6H'

    def pack(self):
        return struct.pack(self.fmt, 
            self.e_ident, self.e_type, self.e_machine, self.e_version,
            self.e_entry, self.e_phoff, self.e_shoff, self.e_flags,
            self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
            self.e_shnum, self.e_shstrndx)

    def unpack(self, b_array):
        upack = struct.unpack(self.fmt, b_array)
        self.__init__(*upack, self.le)

    def __str__(self):
        t_str = f'''E_PHOFF = {self.e_phoff}, E_PHNUM = {self.e_phnum}, E_PHENTSIZE = {self.e_phentsize}'''
        return t_str

class ELFProgramHeader():
    def __init__(self, p_type = 0, p_offset = 0, p_vaddr = 0, p_paddr = 0, 
                p_filesz = 0, p_memsz = 0, p_flags = 0, p_align = 0) -> None:
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align
        self.fmt = '8I'

    def pack(self):
        return struct.pack(self.fmt, self.p_type, self.p_offset, self.p_vaddr, 
            self.p_paddr, self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

    def __str__(self):
        t_str = f'''TYPE = {hex(self.p_type)}, OFFSET = {hex(self.p_offset)}, START_ADDR = {hex(self.p_vaddr)}, END_ADDR = {hex(self.p_vaddr + self.p_filesz)}'''
        return t_str

class ELF():
    def __init__(self, little_endian=True, b_log=True) -> None:
        self.le = little_endian
        self.eh_added = False
        self.bstream = bytearray()
        self.segmentlist = list()
        self.b_log = b_log
        self.elfheader = None
    
    def log_error(self, s: str):
        if self.b_log:
            print(f"[ERROR] : {s} !!!")
        else:
            pass

    def add_eheader_fromb(self, b_array : bytearray, le=True):
        EH = ELFHeader()
        EH.unpack(b_array)
        self.elfheader = EH
        self.eh_added = True

    # TODO: Fix fetching ELF Header directly from ELF file
    def add_eheader_from_elf(self, EH: ELFHeader):
        self.elfheader = EH
        self.eh_added = True

    def add_segment(self, PH: ELFProgramHeader, segdata = None, context = 0):
        self.segmentlist.append({"header": PH, "data": segdata, "context": context})

    def add_segment_from_elf(self, seg: Segment, context = 0):
        TYPE_DICT = {
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
        eph = ELFProgramHeader(
            p_type = TYPE_DICT[seg.header['p_type']],
            p_offset = seg.header['p_offset'],
            p_vaddr = seg.header['p_vaddr'],
            p_paddr = seg.header['p_paddr'],
            p_filesz = seg.header['p_filesz'],
            p_memsz = seg.header['p_memsz'],
            p_flags = seg.header['p_flags'],
            p_align = seg.header['p_align']
        )
        self.add_segment(PH=eph, segdata=bytearray(seg.data()), context=context)

    def __merge_two_segments(self, merger, mergee):
        if merger is None:
            return None
        
        if mergee is None:
            return merger

        alignment = max(merger['header'].p_align, mergee['header'].p_align)
        padding = mergee['header'].p_vaddr - (merger['header'].p_vaddr + merger['header'].p_filesz)

        # add zero padding
        merger['data'].extend(bytearray(padding))

        # now merge the data of mergee
        merger['data'].extend(mergee['data'])

        # update attributes
        merger['header'].p_align = alignment
        orig_size = merger['header'].p_filesz
        merger['header'].p_filesz = orig_size + padding + mergee['header'].p_filesz
        merger['header'].p_memsz = merger['header'].p_filesz

        return merger
    
    def __ismergeable(self, merger, mergee, tol_limit, ignore_context):
        tol_check = False
        context_check = False
        
        if ((mergee['header'].p_vaddr) - (merger['header'].p_vaddr + merger['header'].p_filesz)) <= tol_limit:
            tol_check = True
        else:
            tol_check = False

        if ignore_context:
            context_check = True
        else:
            if mergee['context'] == merger['context']:
                context_check = True
            else:
                context_check = False

        if tol_check and context_check:
            return True
        else:
            return False

    def __get_merged_list(self, in_list, tol_limit, ignore_context):
        merged_list = []

        current_merged_seg = in_list[0]

        for seg in in_list[1:]:
            if self.__ismergeable(current_merged_seg, seg, tol_limit, ignore_context):
                current_merged_seg = self.__merge_two_segments(current_merged_seg, seg)
            else:
                merged_list.append(current_merged_seg)
                current_merged_seg = seg

        merged_list.append(current_merged_seg)

        return merged_list

    def get_merged_list(self, in_list, segmerge, tol_limit, ignore_context):
        segment_count = len(in_list)
        out_list = None
        if segmerge and segment_count > 1:
            out_list = self.__get_merged_list(in_list, tol_limit, ignore_context)
        else:
            out_list = in_list
        
        return out_list

    def merge_segments(self, tol_limit=0, segmerge=False, ignore_context=False):
        # sort the segments
        sorted_list = sorted(self.segmentlist, key = lambda x:x['header'].p_vaddr)
        merged_list = self.get_merged_list(sorted_list, segmerge=segmerge, tol_limit=tol_limit, ignore_context=ignore_context)

        self.segmentlist = merged_list

    def __generate_pht(self):
        # process offsets
        phnum = len(self.segmentlist)
        dummy_ph = ELFProgramHeader()

        offset = ELF_HEADER_SIZE + (phnum * struct.calcsize(dummy_ph.fmt))

        new_list = list()

        for seg in self.segmentlist:
            seg['header'].p_offset = offset
            offset += seg['header'].p_filesz
            new_list.append(seg)

        self.segmentlist = new_list

        for seg in self.segmentlist:
            print(seg['header'])

    def __update_elfh(self):
        ephnum = len(self.segmentlist)
        self.elfheader.e_phnum = ephnum
        self.elfheader.e_phoff = ELF_HEADER_SIZE
        self.bstream.extend(self.elfheader.pack())

    def dbg_dumpsegments(self):
        for s in self.segmentlist:
            print(f"{s['header']}, SIZE = {hex(len(s['data']))} : {s['context']}")

    def make_elf(self, fname):
        # check if elf header is added
        if not self.eh_added:
            self.log_error("ELF Header not added")
            return -1

        # generate PHT
        self.__generate_pht()
        
        # update and add elf header
        self.__update_elfh()
        
        # now add PHT
        for seg in self.segmentlist:
            self.bstream.extend(seg['header'].pack())

        # now add the data
        for seg in self.segmentlist:
            self.bstream.extend(seg['data'])
        
        # the end, now write this to a file
        with open(fname, 'wb+') as f:
            f.write(self.bstream)

class MultiCoreELF():
    def __init__(self, segmerge=False, tol_limit=0, offset_align=0, size_align=0, 
                ignore_context=False, ofname='multicoreelf.out', b_log=True, 
                little_endian=True) -> None:
        self.elf_file_list = list()
        self.metadata_added = False
        self.b_log = b_log
        self.little_endian = little_endian
        self.main_core_idx = 0
        self.elf_header_size = ELF_HEADER_SIZE
        self.tol_limit = tol_limit
        self.offset_align = offset_align
        self.size_align = size_align
        self.segmerge = segmerge
        self.ignore_context = ignore_context
        self.ofname = ofname

    def log_error(self, s: str):
        if self.b_log:
            print(f"[ERROR] : {s} !!!")
        else:
            pass

    def set_main_core_idx(self, idx):
        self.main_core_idx = idx

    def add_elf(self, fname: str):
        self.elf_file_list.append(fname)

    def add_metadata(self, fname: str):
        self.note_segment = metadata.get_note_segment(fname)
        self.metadata_added = True

    def generate_multicoreelf(self, dump_segments=False):
        # check if metadata is added
        if not self.metadata_added:
            self.log_error("Metadata not added to Object")
            return -1

        # Instantiate ELF object and add headers and data to it
        elf_obj = ELF(little_endian=self.little_endian)

        # pick elf header of main core and add the segments to ELF object
        for idx, elf_file in enumerate(self.elf_file_list):
            if idx == self.main_core_idx:
                # get ELF header
                with open(elf_file, 'rb') as f:
                    elf_obj.add_eheader_fromb(f.read(ELF_HEADER_SIZE))
            elf_fp = open(elf_file, 'rb')
            elf_o = ELFFile(elf_fp)
            for segment in elf_o.iter_segments(type='PT_LOAD'):
                if segment.header['p_filesz'] != 0:
                    elf_obj.add_segment_from_elf(segment, context=idx)
            elf_fp.close()
        # segment sort and merge
        elf_obj.merge_segments(tol_limit=self.tol_limit, segmerge=self.segmerge, ignore_context=self.ignore_context)

        # add note segment
        # make final elf
        elf_obj.make_elf(self.ofname)

        if dump_segments:
            elf_obj.dbg_dumpsegments()
