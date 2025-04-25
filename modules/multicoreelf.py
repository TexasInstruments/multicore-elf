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


Multicore ELF module
'''

import os
import struct
import copy
from typing import List
from elftools.elf.elffile import ELFFile
from .elf import ELF
from .elf_structs import ElfConstants as ELFC
from .consts import SSO_CORE_ID
from .note import CustomNote
from .otfaecc_structs import OTFAConfig
from .otfaecc_structs import OTFA_MODE_NO_ENCRYPT
from .otfaecc_structs import OTFA_MODE_GCM
from .otfaecc_structs import OTFA_MODE_CCM
from .gmac_w_ccm import process_chunk
from .eccm import ecc_gen

class OTFAECCMProcessor:
    class regionProperty:
        def __init__(self) -> None:
            self.start:int = 0
            self.size:int = 0
            self.cryptoMode:int = OTFA_MODE_NO_ENCRYPT
            self.mac_size:int = 0
            self.authKey:bytearray = bytearray()
            self.encKey:bytearray = bytearray()
            self.iv:bytearray = bytearray()
            self.ecc_enable:bool = False

    def splitInRanges(self, address:int, size:int, conf:OTFAConfig):
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
                reg1.mac_size = reg2.mac_size = conf.mac_size
                reg2.authKey = otfaRegion.authKey
                reg2.encKey = otfaRegion.encKey
                reg2.iv = otfaRegion.iv
                reg1.ecc_enable = reg2.ecc_enable = otfaRegion.eccEnable
                if reg1.size > 0:
                    subRegs.append(reg1)
                subRegs.append(reg2)
                addressPointer = en

        # Add in any remaining region
        if addressPointer < (startAddress + size):
            reg = OTFAECCMProcessor.regionProperty()
            reg.start = addressPointer
            reg.size = (startAddress + size) - addressPointer
            reg.cryptoMode = OTFA_MODE_NO_ENCRYPT
            reg.mac_size = conf.mac_size
            reg.ecc_enable = False
            subRegs.append(reg)

        if len(subRegs) == 0:
            # there was no overlap of target range with the
            # OTFA region so put the target region as is.
            reg = OTFAECCMProcessor.regionProperty()
            reg.start = address
            reg.size = size
            reg.cryptoMode = OTFA_MODE_NO_ENCRYPT
            reg.mac_size = conf.mac_size
            reg.ecc_enable = False
            subRegs.append(reg)

        return subRegs

    def process_for_safety_and_security(
            self,
            input_buffer: bytes,
            address:int,
            otfaEn:bool,
            eccEn:bool,
            mode: str,
            mac_size: int,
            auth_key: bytes,
            enc_key: bytes,
            iv: bytes
        ) -> bytes:

        def __convert_bytes_to_bits(bytes_data):
            bits = []
            for byte in bytes_data:
                for j in range(8):
                    bits.append((byte >> (j)) & 1)
            return bits

        CHUNK_SIZE = 32
        iv = iv[::-1]
        output_buffer  = bytearray()
        chunks_len = int(len(input_buffer) / CHUNK_SIZE) +\
            (1 if (len(input_buffer) % CHUNK_SIZE) != 0 else 0)
        for i in range(chunks_len):
            chunk = input_buffer[(i*32):((i+1)*32)]
            chunk = chunk.ljust(CHUNK_SIZE, b'\x00')
            chunk_high = chunk[0:16]
            chunk_low = chunk[16:32]
            processed_chunk = bytearray(chunk)
            mac_bytes = bytearray(b'\x00'*int(mac_size))
            ecc_bytes = bytearray()

            if otfaEn == True:
                if (mode == OTFA_MODE_GCM) or (mode == OTFA_MODE_CCM):
                    _,processed_chunk_high = process_chunk(
                        chunk_high, mode, auth_key,
                        enc_key, iv, address + 32*i
                    )
                    tag_low,processed_chunk_low = process_chunk(
                        chunk_low, mode, auth_key,
                        enc_key, iv, address + 32*i + 16
                    )
                    mac_bytes = tag_low[0:int(mac_size)]
                    output_buffer.extend(mac_bytes)
                    processed_chunk = bytearray(processed_chunk_high)
                    processed_chunk.extend(processed_chunk_low)
                else:
                    output_buffer.extend(mac_bytes)

            output_buffer.extend(processed_chunk)

            if eccEn == True:
                _addr = __convert_bytes_to_bits(bytearray(0).ljust(4, b'\x00'))[0:27]
                _mac = mac_bytes.ljust(16, b'\x00')
                processed_chunk_forecc = bytearray()
                processed_chunk_forecc.extend(__convert_bytes_to_bits(processed_chunk))
                processed_chunk_forecc.extend(__convert_bytes_to_bits(_mac))
                processed_chunk_forecc.extend(_addr)
                processed_chunk_forecc.extend(b'\x00')

                a0 = processed_chunk_forecc[(103*0):(103*1)]
                a1 = processed_chunk_forecc[(103*1):(103*2)]
                a2 = processed_chunk_forecc[(103*2):(103*3)]
                a3 = processed_chunk_forecc[(103*3):(103*4)]

                w0 = ecc_gen(a0)
                w1 = ecc_gen(a1)
                w2 = ecc_gen(a2)
                w3 = ecc_gen(a3)

                ecc_bytes.extend(struct.pack('>B', w0)) # ECC P1
                ecc_bytes.extend(struct.pack('>B', w1)) # ECC P2
                ecc_bytes.extend(struct.pack('>B', w2)) # ECC P3
                ecc_bytes.extend(struct.pack('>B', w3)) # ECC P4
                output_buffer.extend(ecc_bytes)

        return output_buffer

    def process(self, buff:bytearray, address:int, size:int, config:OTFAConfig):
        processedData:bytearray = bytearray()
        rgns = self.splitInRanges(address, size, config)
        # if ecc is enabled even in a single region, then enable it in all the regions
        doEnableEcc = False
        doEnableMac = False
        for otfaRgn in config.regionConfigList:
            if otfaRgn.eccEnable == True:
                doEnableEcc = True
            if otfaRgn.cryptoMode != OTFA_MODE_NO_ENCRYPT:
                doEnableMac = True

        # if any crypo is enabled is any region then enable for all regions
        for r in rgns:
            stOffset =  r.start - address
            enOffset = r.start + r.size - address
            dataBuff = bytearray(buff[stOffset:enOffset])
            macSize:int = r.mac_size
            flash_offset = r.start & 0xFFFFFFF
            dataBuff = self.process_for_safety_and_security(
                dataBuff, flash_offset, doEnableMac,
                doEnableEcc, r.cryptoMode, macSize,
                bytearray(r.authKey), bytearray(r.encKey), bytearray(r.iv)
            )
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
        if os.path.exists(filename):
            self.elf_file_list[core_id] = os.path.realpath(filename)
        else:
            self.log_error(f"file \"{filename}\" doesnot exist, skipping this")

    def add_sso(self, fname: str):
        '''Function to add an input SSO file to list'''
        if os.path.exists(fname):
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
                macsz = config.mac_size
        na = int(oldAddress * (32 + eccSz +  macsz) / 32)
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
            if (seg['header'].header.paddr % 32) == 0:
                processedData = processor.process(
                    data, seg['header'].header.paddr,
                    seg['header'].header.memsz, self.otfaConfig
                )
                seg['data'] = processedData
                seg['header'].header.memsz = len(processedData)
                seg['header'].header.filesz = len(processedData)
                paddr = seg['header'].header.paddr
                flashBaseAddress = self.accept_range.start
                _naddr = flashBaseAddress + self.translateAddress(
                    paddr - flashBaseAddress, self.otfaConfig
                )
                seg['header'].header.paddr = _naddr
                seg['header'].header.vaddr = _naddr
            else:
                raise Exception("Segment not aligned to 32B, {}".format(seg['header'].header))
        oelf.segmentlist = segments

    def generate_multicoreelf(self, max_segment_size: int, dump_segments=False, segmerge=False,
        tol_limit=0, ignore_context=False, xlat_file_path=None,
        custom_note: CustomNote = None, add_rs_note=False
    ):
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
        elf_obj.make_elf(
            self.ofname,
            xlat_file_path,
            self.eplist,
            custom_note=custom_note,
            add_rs_note=add_rs_note
        )

        if dump_segments:
            elf_obj.dbg_dumpsegments()

        return 0

if __name__ == "__main__":
    pass
