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
'''Basic structs of OTFA & ECCM module'''

from enum import Enum
from construct import Struct, Int16ul, Int16ub, \
Int32ul, Int32ub, Int64ul, Int64ub, Bytes, IfThenElse, If
from struct import pack, unpack

OTFA_MODE_AUTH = 'auth'
OTFA_MODE_ENCRYPT= 'encrypt'
OTFA_MODE_GCM = 'gcm'
OTFA_MODE_ENCRYPT_AUTH = 'both'
OTFA_MODE_NO_ENCRYPT = 'na'
OTFA_MODE_CCM = 'ccm'

OTFA_MAC_SIZE_4B = 4
OTFA_MAC_SIZE_8B = 8
OTFA_MAC_SIZE_12B = 12
OTFA_MAC_SIZE_16B = 16

OTFA_AES_KEY_SIZE_16B = 16
OTFA_AES_KEY_SIZE_32B = 32

class otfaRegionConfig:
    def __init__(self) -> None:
        self.size:int = 0
        self.start:int = 0
        self.authKeyID:int = 0
        self.encKeyID:int = 0
        self.authKey:str = 'authKey.key'
        self.encKey:str = 'encKey.key'
        self.kdSalt:str = 'kdSalt.txt'
        self.keyFetchMode:int = 1
        self.iv:bytearray = bytearray(8)
        self.cryptoMode:int = OTFA_MODE_NO_ENCRYPT
        self.eccEnable:bool = False 

    def packBytes(self):
        _frm = "<IIbbbbb16s"
        cMode = 0
        if(self.cryptoMode == OTFA_MODE_AUTH):
            cMode = 0
        elif(self.cryptoMode == OTFA_MODE_ENCRYPT):
            cMode = 1
        elif(self.cryptoMode == OTFA_MODE_GCM):
            cMode = 2
        elif(self.cryptoMode == OTFA_MODE_NO_ENCRYPT):
            cMode = 3
        elif(self.cryptoMode == OTFA_MODE_CCM):
            cMode = 4
        else:
            cMode = 5
        return pack(_frm, int(self.size), int(self.start), cMode, 0 if self.eccEnable == False else 1, int(self.authKeyID), int(self.encKeyID), int(self.keyFetchMode), bytes(self.iv))

class OTFAConfig:
    def __init__(self) -> None:
        self.regionConfigList:list[otfaRegionConfig] = list()
        self.mac_align: bool = True
        self.mac_size:int = OTFA_MAC_SIZE_4B
        self.aes_key_size:int =  OTFA_AES_KEY_SIZE_16B
        self.isEnabled: bool = False 

    def packBytes(self):
        rgnBytes = bytes()
        for rgn in self.regionConfigList:
            rgnBytes = rgnBytes + rgn.packBytes()
        _frm = ">bbbbbxxx" + str(len(rgnBytes)) + "s"
        return pack(_frm, self.isEnabled, self.mac_align, self.mac_size, self.aes_key_size, len(self.regionConfigList),rgnBytes)


