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
import subprocess
import sys
import json 
import binascii
from typing import List
from modules.otfaecc_structs import * 
from modules.args import get_args
from modules.multicoreelf import MultiCoreELF, OTFAECCMProcessor
from modules.note import CustomNote
from modules.crypto_hkdf import hkdf

def generate_image(arguments, m_elf: MultiCoreELF, add_rs_note = False, custom_note: CustomNote = None):
    '''Helper function to generate image'''
    for ifname in arguments.core_img:
        m_elf.add_elf(ifname[0])

    if arguments.sso is not None:
        for ifname in arguments.sso:
            if ifname[0] == 'None' or ifname[0] == 'none':
                arguments.sso = None
            else:
                m_elf.add_sso(ifname[0])

    # Set segment merge flag based on input string "true/false"
    segment_merge_flag = False

    if arguments.merge_segments is not None:
        if (arguments.merge_segments == "True" or arguments.merge_segments == "true"):
            segment_merge_flag = True
        else:
            segment_merge_flag = False

    # Set ignore context flag based on input string "true/false"
    ignore_context_flag = False

    if arguments.ignore_context is not None:
        if (arguments.ignore_context == "True" or arguments.ignore_context == "true"):
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
                        if(('size' in conf['regions'][i]) and conf['regions'][i]['size'] != "0x0"):
                            regconf = otfaRegionConfig()
                            size_hex = conf['regions'][i]['size']
                            size_decimal = int(size_hex,16)
                            regconf.size = size_decimal
                            regconf.encKey = [0] * 16
                            regconf.authKey = [0] * 16
                            if('start' in conf['regions'][i]):
                                start_hex = conf['regions'][i]['start']
                                start_decimal = int(start_hex,16)
                                regconf.start = start_decimal
                            if('cryptoMode' in conf['regions'][i]):
                                regconf.cryptoMode = conf['regions'][i]['cryptoMode']
                            if('authKey' in conf['regions'][i]):   
                                    authKeyFile = conf['regions'][i]['authKey']
                                    authKeyValue = None
                                    if regconf.cryptoMode != OTFA_MODE_NO_ENCRYPT: 
                                        with open(authKeyFile,"rb") as fp1:
                                            authKeyValue = fp1.read().strip()
                                            if((conf['regions'][i]['authKeyID']) == 1):
                                                #root key used, derive key using HKDF function
                                                print("\nKey ID = 1, deriving key from authentication key provided")
                                                isalt = get_key_derivation_salt(conf['regions'][i]['kdSalt'])
                                                isalt = bytearray(binascii.unhexlify(isalt))
                                                derivedAuthKey = hkdf(32,authKeyValue,isalt)
                                                fullAuthKey = binascii.hexlify(derivedAuthKey).decode('utf-8')
                                            else:
                                                fullAuthKey = binascii.hexlify(authKeyValue).decode('utf-8')
                                            if('keyFetchMode' in conf['regions'][i]):
                                                regconf.keyFetchMode = conf['regions'][i]['keyFetchMode']
                                                if(conf['regions'][i]['keyFetchMode'] == 1):
                                                    #assign first 16 bytes (value is in hex, so 32 nibbles)
                                                    StringAuthKey = fullAuthKey[:32]
                                                    regconf.authKey = list(bytearray.fromhex(StringAuthKey))
                                                elif(conf['regions'][i]['keyFetchMode'] == 2):
                                                    #assign last 16 bytes
                                                    StringAuthKey = fullAuthKey[-32:]
                                                    regconf.authKey = list(bytearray.fromhex(StringAuthKey))
                                                else:
                                                    # Error, keyFetchMode should be an integer between 1 and 3
                                                    print("Please enter valid keyFetchMode")                                        
                            if('encKey' in conf['regions'][i]):
                                    encKeyFile = conf['regions'][i]['encKey']
                                    encKeyValue = None
                                    if regconf.cryptoMode != OTFA_MODE_NO_ENCRYPT: 
                                        with open(encKeyFile,"rb") as fp2:
                                            encKeyValue = fp2.read().strip()
                                            if((conf['regions'][i]['encKeyID']) == 1):
                                                #root key used, derive key using HKDF function
                                                print("\nKey ID = 1, deriving key from encryption key provided")
                                                isalt = get_key_derivation_salt(conf['regions'][i]['kdSalt'])
                                                isalt = bytearray(binascii.unhexlify(isalt))
                                                derivedEncKey = hkdf(32,encKeyValue,isalt)
                                                fullEncKey = binascii.hexlify(derivedEncKey).decode('utf-8')
                                            else:
                                                fullEncKey = binascii.hexlify(encKeyValue).decode('utf-8')
                                            if('keyFetchMode' in conf['regions'][i]):
                                                if(conf['regions'][i]['keyFetchMode'] == 1):
                                                    #assign first 16 bytes (value is in hex, so 32 nibbles)
                                                    StringEncKey = fullEncKey[:32]
                                                    regconf.encKey = list(bytearray.fromhex(StringEncKey))
                                                elif(conf['regions'][i]['keyFetchMode'] == 2):
                                                    #assign last 16 bytes
                                                    StringEncKey = fullEncKey[-32:]
                                                    regconf.encKey = list(bytearray.fromhex(StringEncKey))
                                                else:
                                                    # Error, keyFetchMode should be an integer between 1 and 3
                                                    print("Please enter valid keyFetchMode")
                            if('authKeyID' in conf['regions'][i]): 
                                regconf.authKeyID = conf['regions'][i]['authKeyID']
                            if('encKeyID' in conf['regions'][i]): 
                                regconf.encKeyID = conf['regions'][i]['encKeyID']
                            regconf.iv = gen_IV()
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
            retConf.aes_key_size = OTFA_AES_KEY_SIZE_16B 
    
    return retConf 

def get_key_derivation_salt(kd_salt_file_name: str) -> str:
    kd_salt = None
    if (not os.path.exists(kd_salt_file_name)):
        # Error, key derivation salt has to be given
        print("Please give the key derivation salt file name. It's either missing or file not found!")
        exit(1)
    else:
        with open(kd_salt_file_name, "r") as f:
            kd_salt = f.read()
            kd_salt = kd_salt.strip('\n')

    return kd_salt

def gen_IV(width=16) -> str:
    IVgen = ""
    try:
        IVgen = subprocess.run(["openssl", "rand", "-hex", "16"], check=True, text=True,capture_output=True)
        IVgen_string = IVgen.stdout.strip()
        IVgen_bytes = bytearray(binascii.unhexlify(IVgen_string))
        print(f"\nUsing randomly generated IV : {IVgen_string}\n")
        return IVgen_bytes
    except subprocess.CalledProcessError as e:
        print(f"OpenSSL command failed: {e}")
        sys.exit()

def main():
    '''Main function'''
    arguments = get_args()

    otfaConfigFile:str|None = arguments.otfaConfigFile
    otfaConfg:OTFAConfig|None = OTFAConfig()

    if otfaConfigFile is None or os.path.exists(os.path.abspath(otfaConfigFile)) is False:
        otfaConfigFile = None 
        otfaConfg.isEnabled = False
    else:
        otfaConfg = getValidateOtfaConfig(otfaConfigFile)

    if arguments.xlat is None or arguments.xlat == "none" or arguments.xlat == "None":
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
    generate_image(arguments, m_elf, add_rs_note=True, custom_note=otfaConfigNote)

if __name__ == "__main__":
    main()
