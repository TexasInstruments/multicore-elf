'''
Copyright (C) 2024 Texas Instruments Incorporated

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the
  distribution.

  Neither the name of Texas Instruments Incorporated nor the names of
  its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

'''Multicore ELF module'''

import os
import copy
from typing import List
from datetime import datetime
from elftools.elf.elffile import ELFFile
from .elf import ELF
from .elf_structs import ElfConstants as ELFC
from .consts import SSO_CORE_ID
from .note import CustomNote
from .otfaecc_structs import *
from .gmac import enc_process_data
from .eccm import append_ecc

class OTFAECCMProcessor:
    class regionProperty:
        def __init__(self) -> None:
            self.start:int = 0
            self.size:int = 0
            self.cryptoMode:int =0
            self.mac_size:int = 0
            self.authKey:bytearray = bytearray()
            self.encKey:bytearray = bytearray()
            self.iv:bytearray = bytearray()
            self.ecc_enable:bool = False 

    def splitInRanges(self, address:int, size:int, conf:OTFAConfig):
        print(f"processing data for start = {hex(address)}, size = {hex(size)}")
        startAddress = address
        endAddress = address + size
        addressPointer = startAddress
        subRegs:List[OTFAECCMProcessor.regionProperty] = list()

        for otfaRegion in conf.regionConfigList:
            st = max(addressPointer, otfaRegion.start)
            en = min(endAddress, otfaRegion.size + otfaRegion.start)
            if en > st:
                reg1 = OTFAECCMProcessor.regionProperty()
                reg2 = OTFAECCMProcessor.regionProperty()
                reg1.start = addressPointer
                reg1.size = st - addressPointer
                reg2.start = st
                reg2.size = en - st 
                reg2.cryptoMode = otfaRegion.cryptoMode
                reg2.mac_size = conf.mac_size
                reg2.authKey = otfaRegion.authKey
                reg2.encKey = otfaRegion.encKey
                reg2.iv = otfaRegion.iv
                reg2.ecc_enable = otfaRegion.eccEnable
                if(reg1.size > 0):
                    subRegs.append(reg1)
                subRegs.append(reg2)
                addressPointer = en 

        # Add in any remaining region
        if(addressPointer < (startAddress + size)):
            reg = OTFAECCMProcessor.regionProperty()
            reg.start = addressPointer
            reg.size = (startAddress + size) - addressPointer
            reg.cryptoMode = OTFA_MODE_NO_ENCRYPT
            reg.ecc_enable = False
            subRegs.append(reg)

        if len(subRegs) == 0:
            # there was no overlap of target range with the 
            # OTFA region so put the target region as is.
            reg = OTFAECCMProcessor.regionProperty()
            reg.start = address
            reg.size = size
            reg.cryptoMode = OTFA_MODE_NO_ENCRYPT
            reg.ecc_enable = False
            subRegs.append(reg)

        for r in subRegs:
            print(f"start: {hex(r.start)}, size: {hex(r.size)}, eccEn: {r.ecc_enable}, cryptoMode: {r.cryptoMode}")
        
        return subRegs
    
    def process(self, buff:bytearray, address:int, size:int, config:OTFAConfig):
        processedData:bytearray = bytearray()
        rgns = self.splitInRanges(address, size, config)
        # if ecc is enabled even in a single region, then enable it in all the regions
        doEnableEcc = False
        for otfaRgn in config.regionConfigList:
            if(otfaRgn.eccEnable == True):
                doEnableEcc = True
                break
        # if any crypo is enabled is any region then enable for all regions
        for r in rgns:
            stOffset = (r.start - address)
            enOffset = (r.start + r.size - address)
            dataBuff = bytearray(buff[stOffset:enOffset])
            if(r.cryptoMode != OTFA_MODE_NO_ENCRYPT):
                dataBuff = enc_process_data(dataBuff, r.cryptoMode, r.mac_size, r.start, bytearray(r.authKey), bytearray(r.encKey), bytearray(r.iv))
            if(doEnableEcc == True):
                dataBuff = append_ecc(dataBuff)
            processedData.extend(dataBuff)
        return processedData

class MultiCoreELF():
    '''Multicore ELF Object'''
    def __init__(self, ofname='multicoreelf.out', little_endian=True,
                ignore_range=None, accept_range=None) -> None:
        self.elf_file_list = {}
        self.metadata_added = False
        self.little_endian = little_endian
        self.ofname = ofname
        self.ignore_range = ignore_range
        self.accept_range = accept_range
        self.eplist = {}
        self.otfaConfig:OTFAConfig = OTFAConfig()

    def log_error(self, err_str: str):
        '''Error logging fxn'''
        print(f"[ERROR] : {err_str} !!!")

    def add_elf(self, fname: str):
        '''Function to add an input ELF file to list'''
        # Try to split the fname into core ID and filename
        delim = ':'
        core_id, filename = fname.split(delim)
        if(os.path.exists(filename)):
            self.elf_file_list[core_id] = os.path.realpath(filename)
        else:
            self.log_error(f"file \"{filename}\" doesnot exist, skipping this")

    def add_sso(self, fname: str):
        '''Function to add an input SSO file to list'''
        if(os.path.exists(fname)):
            self.elf_file_list[SSO_CORE_ID] = os.path.realpath(fname)
        else:
            self.log_error(f"file \"{fname}\" doesnot exist, skipping this")

    def __check_for_elf64(self):
        class_index = ELFC.ELFCLASS_IDX.value
        is64 = False
        core64 = 0
        for core_id, fname in self.elf_file_list.items():
            with open(fname, 'rb') as f_ptr:
                check_bytes = f_ptr.read(class_index + 1)
                if check_bytes[class_index] == ELFC.ELFCLASS64.value:
                    is64 = True
                    core64 = core_id
                    break
        return is64, core64

    def __check_range(self, phent):
        i_range = True
        a_range = True

        if self.ignore_range is not None:
            i_range = not bool(self.ignore_range.start <= phent['p_vaddr'] <= self.ignore_range.end)

        if self.accept_range is not None:
            a_range = bool(self.accept_range.start <= phent['p_vaddr'] <= self.accept_range.end)

        return (i_range and a_range)
    
    def translateAddress(self, oldAddress:int, config:OTFAConfig) -> int: 
        na = 0
        eccSz = 0   
        macsz = 0
        for rgn in config.regionConfigList:
            if rgn.eccEnable == True:
                eccSz = 4 
            if rgn.cryptoMode != OTFA_MODE_NO_ENCRYPT:
                macsz = 4 * config.mac_size
        na = int(oldAddress * (32 + eccSz +  macsz) / 32)
        print("Translated address {} to {}".format(hex(oldAddress), hex(na)))
        return na  

    def process_for_otfaeccm(self, oelf:ELFFile) -> None:
        if(self.otfaConfig.isEnabled == False or len(oelf.segmentlist) == 0):
            return
        # deepcopy the segmentlist and then update 
        # each segment 
        processor = OTFAECCMProcessor()
        segments = copy.copy(oelf.segmentlist)
        oelf.segmentlist = []
        for seg in segments:
            data = seg['data']
            if(seg['header'].header.paddr % 32 == 0):
                print("Encrypting {}".format(seg['header'].header))
                t0 = datetime.now()
                processedData = processor.process(data, seg['header'].header.paddr, seg['header'].header.memsz, self.otfaConfig)
                t1 = datetime.now()
                print("Encryption done...time taken = {}".format(t1-t0))
                seg['data'] = processedData
                seg['header'].header.memsz = seg['header'].header.filesz = len(processedData)
                paddr = seg['header'].header.paddr
                flashBaseAddress = self.accept_range.start 
                seg['header'].header.paddr = seg['header'].header.vaddr = flashBaseAddress + self.translateAddress(paddr - flashBaseAddress, self.otfaConfig)
                with open("processed_data_{}.bin".format(seg['header'].header.vaddr), "wb") as of:
                    of.write(bytearray(processedData))
                with open("raw_data_{}.bin".format(seg['header'].header.vaddr), "wb") as of:
                    of.write(bytearray(data))
                    
            else:
                raise Exception("Segment not aligned to 32B, {}".format(seg['header'].header)) 
        oelf.segmentlist = segments

    def generate_multicoreelf(self, max_segment_size: int, dump_segments=False, segmerge=False,
        tol_limit=0, ignore_context=False, xlat_file_path=None, custom_note: CustomNote = None, add_rs_note=False):
        '''Function to finally generate the multicore elf file'''
        # Check if there are any 64 bit ELFs in the list
        is64, core64 = self.__check_for_elf64()

        # Instantiate ELF object and add headers and data to it
        elf_obj = ELF(little_endian=self.little_endian)

        # pick elf header of main core and add the segments to ELF object
        # if there are ELF64s, copy ELF header from the ELF64. Else pick the first one

        if is64:
            elf_obj.add_eheader_from_elf(self.elf_file_list[core64])
        else:
            fname = next(iter(self.elf_file_list.values()))
            elf_obj.add_eheader_from_elf(fname)

        for core_id, fname in self.elf_file_list.items():
            elf_fp = open(fname, 'rb')
            elf_o = ELFFile(elf_fp)
            self.eplist[core_id] = elf_o.header['e_entry']
            for segment in elf_o.iter_segments(type='PT_LOAD'):
                if (segment.header['p_filesz'] != 0) and self.__check_range(segment.header):
                    elf_obj.add_segment_from_elf(segment, max_segment_size, context=core_id)
            elf_fp.close()
        # segment sort and merge
        elf_obj.merge_segments(tol_limit=tol_limit,
                            segmerge=segmerge,
                            ignore_context=ignore_context)
        
        # for all the segments perform the encryption/ECC processing and change the
        # load address and the size 
        self.process_for_otfaeccm(elf_obj)
        
        # add note segment
        # make final elf
        elf_obj.make_elf(self.ofname, xlat_file_path, self.eplist, custom_note=custom_note, add_rs_note=add_rs_note)

        if dump_segments:
            elf_obj.dbg_dumpsegments()

        return 0

if __name__ == "__main__":
    pass
