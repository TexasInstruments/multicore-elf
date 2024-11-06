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

'''Main script to generate the multicore ELF image'''
import os 
import json 
from typing import List
from modules.otfaecc_structs import * 
from modules.args import get_args
from modules.multicoreelf import MultiCoreELF, OTFAECCMProcessor
from modules.note import CustomNote

def generate_image(arguments, m_elf: MultiCoreELF, add_rs_note = False, custom_note: CustomNote = None):
    '''Helper function to generate image'''
    for ifname in arguments.core_img:
        m_elf.add_elf(ifname[0])

    if arguments.sso is not None:
        for ifname in arguments.sso:
            m_elf.add_sso(ifname[0])

    # Set segment merge flag based on input string "true/false"
    segment_merge_flag = False

    if (arguments.merge_segments.upper() == "TRUE"):
        segment_merge_flag = True
    else:
        segment_merge_flag = False

    # Set ignore context flag based on input string "true/false"
    ignore_context_flag = False

    if (arguments.ignore_context.upper() == "TRUE"):
        ignore_context_flag = True
    else:
        ignore_context_flag = False

    # Generate multicoreelf
    m_elf.generate_multicoreelf(max_segment_size=arguments.max_segment_size,
                                segmerge=segment_merge_flag,
                                tol_limit=arguments.tolerance_limit,
                                ignore_context=ignore_context_flag,
                                xlat_file_path=arguments.xlat,
                                custom_note=custom_note,
                                add_rs_note=add_rs_note)

def getValidateOtfaConfig(filePath:str) -> OTFAConfig:
    retConf:OTFAConfig = OTFAConfig()
    with open(filePath, "r") as fp:
        conf = json.load(fp)
        retConf.isEnabled = False 
        otfaReg:list[otfaRegionConfig] = list()
        if('regions' in conf):
            if(type(conf['regions']) == type(list())):
                if(len(conf['regions']) > 0):
                    for i in range(len(conf['regions'])):
                        if(('size' in conf['regions'][i]) and conf['regions'][i]['size'] > 0):
                            regconf = otfaRegionConfig()
                            regconf.size = conf['regions'][i]['size']
                            if('start' in conf['regions'][i]):
                                regconf.start = conf['regions'][i]['start']
                            if('authKey' in conf['regions'][i]):
                                regconf.authKey = conf['regions'][i]['authKey']
                            if('encKey' in conf['regions'][i]):
                                regconf.encKey = conf['regions'][i]['encKey']
                            if('iv' in conf['regions'][i]):
                                regconf.iv = conf['regions'][i]['iv']
                            if('cryptoMode' in conf['regions'][i]):
                                regconf.cryptoMode = conf['regions'][i]['cryptoMode']
                            if('eccEnable' in conf['regions'][i]):
                                regconf.eccEnable = conf['regions'][i]['eccEnable']
                            otfaReg.append(regconf)
                    if(len(otfaReg) > 0):
                        retConf.isEnabled = True 
                        retConf.regionConfigList = otfaReg
        if('mac_align' not in conf):
            retConf.mac_align = True 
        if('mac_size' not in conf):
            retConf.mac_size = 4 
        if('aes_key_size' not in conf):
            retConf.aes_key_size = OTFA_AES_KEY_SIZE_128BIT 
    return retConf 

def main():
    '''Main function'''
    arguments = get_args()

    otfaConfigFile:str|None = arguments.otfaConfigFile
    otfaConfg:OTFAConfig|None = OTFAConfig()

    if otfaConfigFile is not None and os.path.exists(os.path.abspath(otfaConfigFile)) is False:
        otfaConfigFile = None 
        otfaConfg.isEnabled = False
    else:
        otfaConfg = getValidateOtfaConfig(otfaConfigFile)

    if arguments.xlat is not None and arguments.xlat.strip() == "":
        arguments.xlat = None

    is_xip = bool(arguments.xip is not None)

    ignore_range = None
    accept_range = None
    otfaConfigNote:CustomNote = CustomNote("otfaConfig", otfaConfg.packBytes())

    if is_xip:
        ignore_range = accept_range = arguments.xip

        m_elf_xip = MultiCoreELF(
            ofname=f"{arguments.output}_xip",
            accept_range=accept_range
            )
        m_elf_xip.otfaConfig = otfaConfg
        generate_image(arguments, m_elf_xip, add_rs_note=False, custom_note=otfaConfigNote)

    m_elf = MultiCoreELF(
        ofname=arguments.output,
        ignore_range=ignore_range
        )
    m_elf_xip.otfaConfig.isEnabled = False
    generate_image(arguments, m_elf, add_rs_note=True, custom_note=otfaConfigNote)

if __name__ == "__main__":
    main()
