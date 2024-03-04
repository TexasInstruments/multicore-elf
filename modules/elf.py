'''ELF Module'''
from elftools.elf.elffile import Segment
from .elf_structs import elf_header, elf_prog_header
from .elf_structs import ElfConstants as ELFC, PT_TYPE_DICT

class ELFHeader():
    '''ELF Header'''
    def __init__(self, data, little_endian = True):
        self.data = None
        self.is64 = False
        self.islittle = little_endian
        self.size = ELFC.ELF32_SIZE.value
        file_init = False
        class_idx = ELFC.ELFCLASS_IDX.value
        if isinstance(data, bytearray):
            self.data = data
        elif isinstance(data, str):
            file_init = True
            with open(data, 'rb') as f_ptr:
                self.data = f_ptr.read(class_idx+1)
        else:
            raise ValueError("Input data must be bytearray or a filename")

        self.is64 = bool(self.data[class_idx] == ELFC.ELFCLASS64.value)

        if self.is64:
            self.size = ELFC.ELF64_SIZE.value

        if file_init:
            with open(data, 'rb') as f_ptr:
                self.data = f_ptr.read(self.size)

        if len(self.data) != self.size:
            raise ValueError("Given file doesn't have enough bytes for ELF header")

        self.format = elf_header(self.islittle, self.is64)
        self.header = self.format.parse(self.data)

    def get_size(self):
        '''Function to get the serialized size of header'''
        return self.size

    def pack(self):
        '''Function to get the serialized size'''
        return self.format.build(self.header)

class ELFProgramHeader():
    '''ELF Program Header'''
    def __init__(self, data, little_endian=True, is64=False):
        self.data = None
        self.is64 = is64
        self.islittle = little_endian
        if self.is64:
            self.size = ELFC.ELFPH64_SIZE.value
        else:
            self.size = ELFC.ELFPH32_SIZE.value

        if isinstance(data, Segment):
            self.data = data
        else:
            raise ValueError("Input data must be of Segment type")

        self.format = elf_prog_header(self.islittle, self.is64)
        self.header = self.format.parse(bytearray(self.size))

        self.header.type = PT_TYPE_DICT[data.header['p_type']]
        if is64:
            self.header.flags_64 = data.header['p_flags']
        else:
            self.header.flags_32 = data.header['p_flags']

        self.header.offset = data.header['p_offset']
        self.header.vaddr  = data.header['p_vaddr']
        self.header.paddr  = data.header['p_paddr']
        self.header.filesz = data.header['p_filesz']
        self.header.memsz  = data.header['p_memsz']
        self.header.align  = data.header['p_align']

    def get_size(self):
        '''Function to get the serialized size of header'''
        return self.size

    def pack(self):
        '''Function to get the serialized data'''
        return self.format.build(self.header)

class ELF():
    '''ELF Class'''
    def __init__(self, little_endian=True, b_log=True) -> None:
        self.little_endian = little_endian
        self.eh_added = False
        self.bstream = bytearray()
        self.segmentlist = list()
        self.b_log = b_log
        self.elfheader = None

    def log_error(self, my_str: str):
        '''Error logging function'''
        if self.b_log:
            print(f"[ERROR] : {my_str} !!!")
        else:
            pass

    def add_eheader_fromb(self, b_array : bytearray):
        '''Function to add ELF header from a bytearray'''
        self.elfheader = ELFHeader(b_array)
        self.eh_added = True

    def add_eheader_from_elf(self, elf_fname):
        '''Function to add ELF header from an existing ELF file'''
        self.elfheader = ELFHeader(elf_fname)
        self.eh_added = True

    def add_segment(self, phent: ELFProgramHeader, segdata = None, context = 0):
        '''Function to add segment to the internal segment list'''
        self.segmentlist.append({"header": phent, "data": segdata, "context": context})

    def add_segment_from_elf(self, segment, context = 0):
        '''Function to add segment from ELFFile segment list'''
        phent = ELFProgramHeader(segment)
        self.add_segment(phent=phent, segdata=bytearray(segment.data()), context=context)

    def __merge_two_segments(self, merger, mergee):
        if merger is None:
            return None

        if mergee is None:
            return merger

        alignment = max(merger['header'].header.align, mergee['header'].header.align)
        start = mergee['header'].header.vaddr
        end = merger['header'].header.vaddr + merger['header'].header.filesz
        padding = (start-end)

        # add zero padding
        merger['data'].extend(bytearray(padding))

        # now merge the data of mergee
        merger['data'].extend(mergee['data'])

        # update attributes
        merger['header'].header.align = alignment
        orig_size = merger['header'].header.filesz
        merger['header'].header.filesz = orig_size + padding + mergee['header'].header.filesz
        merger['header'].header.memsz = merger['header'].header.filesz

        return merger

    def __ismergeable(self, merger, mergee, tol_limit, ignore_context):
        addr_check = False
        context_check = False

        end = (merger['header'].header.vaddr + merger['header'].header.filesz)
        start = (mergee['header'].header.vaddr)
        addr_check = bool(((start - end) <= tol_limit) and (start != merger['header'].header.vaddr))

        if ignore_context:
            context_check = True
        else:
            context_check = bool(mergee['context'] == merger['context'])

        return bool(addr_check and context_check)

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
        '''Returns a list of segments with segments merged according to the arguments provided'''
        segment_count = len(in_list)
        out_list = None
        if segmerge and segment_count > 1:
            out_list = self.__get_merged_list(in_list, tol_limit, ignore_context)
        else:
            out_list = in_list

        return out_list

    def merge_segments(self, tol_limit=0, segmerge=False, ignore_context=False):
        '''Runs the merge operation on the internal list of segments'''
        # sort the segments
        sorted_list = sorted(self.segmentlist, key = lambda x:x['header'].header.vaddr)
        merged_list = self.get_merged_list(sorted_list,
                                        segmerge=segmerge,
                                        tol_limit=tol_limit,
                                        ignore_context=ignore_context)

        self.segmentlist = merged_list

    def __generate_pht(self):
        # process offsets
        phnum = len(self.segmentlist)
        random_ph = self.segmentlist[1] # segment 0 is always note segment

        offset = self.elfheader.get_size() + (phnum * random_ph['header'].get_size())

        new_list = []

        for seg in self.segmentlist:
            seg['header'].header.offset = offset
            offset += seg['header'].header.filesz
            new_list.append(seg)

        self.segmentlist = new_list

    def __update_elfh(self):
        ephnum = len(self.segmentlist)
        self.elfheader.header.e_phnum = ephnum
        self.elfheader.header.e_phoff = self.elfheader.get_size()
        self.elfheader.header.e_shoff = 0
        self.elfheader.header.e_shnum = 0
        self.bstream.extend(self.elfheader.pack())

    def dbg_dumpsegments(self):
        '''Debug function to dump the segments of the ELF Object'''
        for seg in self.segmentlist:
            print(f"{seg['header'].header}, SIZE = {hex(len(seg['data']))} : {seg['context']}")

    def make_elf(self, fname):
        '''Create the elf file and write it to the filename provided'''
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
        with open(fname, 'wb+') as file_p:
            file_p.write(self.bstream)

        return 0
