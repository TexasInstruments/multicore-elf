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

'''Post processing for GMAC and CCM'''

import io
import platform
import sys
import os 
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ctypes import *
from typing import List, Optional 

OS_NAME = sys.platform
PYTHON_ARCH = list(platform.architecture())[0]
WIN_MINGW_GCC_MACHINE_64BIT = 'x86_64-w64-mingw32'
WIN_MINGW_GCC_MACHINE_32BIT = 'mingw32'
LINUX_GNU_GCC_MACHINE_64BIT = 'x86_64-linux-gnu'
LINUX_GNU_GCC_MACHINE_32BIT = 'gnu'
APPLE_GNU_GCC_64BIT          = 'arm64-apple-darwin'

if OS_NAME != "win32" and OS_NAME != "linux" and OS_NAME != "darwin":
    raise "Unsupported OS"

class c_gmac_wrapper:
    def __init__(self) -> None:
    
      def get_shared_lib_name():
          f = "gmac.{}.{}.{}"
          if PYTHON_ARCH == "64bit" and OS_NAME == "win32":
              return f.format(WIN_MINGW_GCC_MACHINE_64BIT, OS_NAME, "dll")
          elif PYTHON_ARCH == "32bit" and OS_NAME == "win32":
              return f.format(WIN_MINGW_GCC_MACHINE_32BIT, OS_NAME, "dll")
          elif PYTHON_ARCH == "64bit" and OS_NAME == "linux":
              return f.format(LINUX_GNU_GCC_MACHINE_64BIT, OS_NAME, "so")
          elif PYTHON_ARCH == "32bit" and OS_NAME == "linux":
              return f.format(WIN_MINGW_GCC_MACHINE_32BIT, OS_NAME, "so")
          elif PYTHON_ARCH == "64bit" and OS_NAME == "darwin":
              return f.format(APPLE_GNU_GCC_64BIT, OS_NAME, "dylib")
          else:
            raise "Unsupported OS"
          
      file_name: str = get_shared_lib_name()

      so_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../", "c_modules", "gmac", "dist", file_name))

      self.so_gmac = CDLL(so_file)
      self.fnx = self.so_gmac.cGmac
      self.fnx.argtypes =\
        [POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint32), POINTER(c_uint64), POINTER(c_uint32)]


    def call(self, ctlo:List[int], ctHi:List[int], aesData:List[int], keyA:List[int])->Optional[List[int]]:
      ct_lo = (c_uint32*4)(*ctlo)
      ct_hi = (c_uint32*4)(*ctHi)
      ct_aes_data = (c_uint32*4)(*aesData)
      key_a = (c_uint64*2)(*keyA)
      output = (c_uint32*4)()        
      self.fnx(ct_lo, ct_hi, ct_aes_data, key_a, output)
      return list(output)

c_gmac = c_gmac_wrapper()

UINT64_MAX = 0xFFFFFFFFFFFFFFFF
aes_data = [0]*4
ct_lo = [0]*4
ct_hi = [0]*4
ccm_lo = [0]*16
# wr_mac_addr = 0x0000
def cmac(auth_key,ct):
   backend = default_backend()
   chunk = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
   rev_ct=reverse_array(ct)
   auth_key = reverse_array(auth_key)
   cipher = Cipher(algorithms.AES(auth_key), modes.CTR(rev_ct), backend=backend)
   encryptor = cipher.encryptor()
   ciphertext = encryptor.update(chunk) + encryptor.finalize()
   ciphertext=reverse_array(ciphertext)   
   return ciphertext


def aes_data_mac(enc_key, iv, address):
    chunk = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    backend = default_backend()
    # Copy the original IV to ensure it is re-initialized for each chunk
    iv_copy = iv.copy()

    # XOR the IV with the current address
    iv_copy = xor_address_with_iv(iv_copy, address)

    enc_key = reverse_array(enc_key)
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv_copy), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(chunk) + encryptor.finalize()
    ciphertext=reverse_array(ciphertext)    
    return ciphertext

def bit_rev(data_in,bit_len):

    NO_OF_BITS = bit_len;
    reverse_num = 0;
    for i in range(NO_OF_BITS):
      if ((data_in & (1 << i))):
        reverse_num |= 1 << ((NO_OF_BITS - 1) - i);
    
    return reverse_num


# NOTE ONLY ENCRYPTION IS TESTED (AUTHENTICATION AND AUTHENTICATION + ENCRYPTION YET TO BE TESTED)

def reverse_array(arr):
#"""Reverses the order of elements in an array. Args: arr: The list or array to be reversed. Returns: A new list with the elements in reversed order. """
    return arr[::-1]


def xor_address_with_iv(iv, address):
    address_bytes = address.to_bytes(4, byteorder='big')
    # XOR the last 4 bytes of the IV with the address bytes
    iv[-4:] = bytes(a ^ b for a, b in zip(iv[-4:], address_bytes))
    return iv


def ghash(input_data, key_a):
  '''
        GHASH functions performs multiply and accumulate on single cipher data and plain text
  '''
  a_hi = [0] * 32
  a_lo = [0] * 32
  z_hi = [0] * 32
  z_lo = [0] * 32
  output = [0] * 4
  wz_hi = 0
  wz_lo = 0
  rresult_hi = 0
  rresult_lo = 0

  input_reorg = [0]*4
  rresult_hi = 0; rresult_lo = 0;

  for i in range(4):
    input_reorg[i] = input_data[3-i]

  
  for i in range(4):
    data_in = input_reorg[i]
    for j in range(32):
      bit_rep = UINT64_MAX if (((data_in >> (31-j) )&1) == 1) else 0
      a_hi[j] = (key_a[1] & bit_rep) 
      a_lo[j] = (key_a[0] & bit_rep)

    for j in range(32):
      z_lo[j] = 0
      z_hi[j] = 0
      
      if(j==0):
        
        #BIT-0
        bit_mul = (a_lo[0] & 0x1) ^ (rresult_hi>>63);
        wz_lo =  (wz_lo & ~(0x1)) | (bit_mul & 0x1);
  
        #BIT-1
        bit_mul = (rresult_lo & 0x1) ^ ((a_lo[0] >>0x1) & 0x1) ^ (rresult_hi>>63) ;
        wz_lo =  (wz_lo & ~((0x1)<<1)) | ((bit_mul & 0x1)<<1);
  
  
        #BIT-2
        bit_mul = ((rresult_lo>>0x1) & 0x1) ^ ((a_lo[0] >>0x2) & 0x1) ^ (rresult_hi>>63) ;
        wz_lo =  (wz_lo & ~((0x1)<<2)) | ((bit_mul & 0x1)<<0x2);

        #BIT-3:6
        for k in range(3, 7):
          bit_mul = ((rresult_lo >> (k - 1)) & 1) ^ ((a_lo[0] >> k) & 1)
          wz_lo = (wz_lo & ~(1 << k)) | ((bit_mul & 1) << k)

        #BIT-7
        bit_mul = ((rresult_lo>>0x6) & 0x1) ^ ((a_lo[0] >>0x7) & 0x1) ^ (rresult_hi>>63) ;
        wz_lo =  (wz_lo & ~((0x1)<<7)) | ((bit_mul & 0x1)<<0x7);

        for k in range(8, 128):
          if k <= 63:
            bit_mul = ((rresult_lo >> (k - 1)) & 1) ^ ((a_lo[0] >> k) & 1)
            wz_lo = (wz_lo & ~(1 << (k % 64))) | ((bit_mul & 1) << (k % 64))
          elif k == 64:
            bit_mul = ((rresult_lo >> (k - 1)) & 1) ^ ((a_hi[0] >> (k % 64)) & 1)
            wz_hi = (wz_hi & ~(1 << (k % 64))) | ((bit_mul & 1) << (k % 64))
          else:
            bit_mul = ((rresult_hi >> ((k - 1) % 64)) & 1) ^ ((a_hi[0] >> (k % 64)) & 1)
            wz_hi = (wz_hi & ~(1 << (k % 64))) | ((bit_mul & 1) << (k % 64))

        if i == 0:
          z_hi[0] = a_hi[0]
          z_lo[0] = a_lo[0]
        else:
          z_hi[0] = wz_hi
          z_lo[0] = wz_lo

      else:

        #BIT-0
        bit_mul = (a_lo[j] & 0x1) ^ (z_hi[j-1] >>63);
        z_lo[j] = z_lo[j] | (bit_mul & 0x1) ;
  
        #BIT-1
        bit_mul = (z_lo[j-1] & 0x1 ) ^ ((a_lo[j] >> 0x1) & 0x1) ^ (z_hi[j-1] >>63);
        z_lo[j] = z_lo[j] | ((bit_mul & 0x1) << 0x1);
  
  
        #BIT-2
        bit_mul = ((z_lo[j-1] >> 0x1) & 0x1 ) ^ ((a_lo[j]>>0x2) & 0x1) ^ (z_hi[j-1] >>63);
        z_lo[j] = z_lo[j] | ((bit_mul & 0x1) << 0x2);

        # BIT-3:6
        for k in range(3, 7):
          bit_mul = ((z_lo[j - 1] >> (k - 1)) & 1) ^ ((a_lo[j] >> k) & 1)
          z_lo[j] = z_lo[j] | ((bit_mul & 1) << k)

        # BIT-7
        bit_mul = ((z_lo[j - 1] >> 6) & 1) ^ ((a_lo[j] >> 7) & 1) ^ (z_hi[j - 1] >> 63)
        z_lo[j] = z_lo[j] | ((bit_mul & 1) << 7)

        # BIT-8
        for k in range(8, 128):
          if k <= 63:
            bit_mul = ((z_lo[j - 1] >> (k - 1)) & 1) ^ ((a_lo[j] >> k) & 1)
            z_lo[j] = z_lo[j] | ((bit_mul & 1) << k)
          elif k == 64:
            bit_mul = ((z_lo[j - 1] >> (k - 1)) & 1) ^ ((a_hi[j] >> (k % 64)) & 1)
            z_hi[j] = z_hi[j] | ((bit_mul & 1) << (k % 64))
          else:
            bit_mul = ((z_hi[j - 1] >> ((k - 1) % 64)) & 1) ^ ((a_hi[j] >> (k % 64)) & 1)
            z_hi[j] = z_hi[j] | ((bit_mul & 1) << (k % 64))

    rresult_hi = z_hi[31]
    rresult_lo = z_lo[31]

  output[0] = (rresult_lo & 0xFFFFFFFF)
  output[1] = (rresult_lo >> 32) & 0xFFFFFFFF
  output[2] = rresult_hi & 0xFFFFFFFF
  output[3] = (rresult_hi >> 32) & 0xFFFFFFFF

  return output


def gmac(ct_lo, ct_hi, data_aes, key_a):
  ghash_lo = []
  ghash_hi = []
  ghash_hi_flip = [0]*4
  ct_lo_flip = [0]*4
  ct_hi_flip = [0]*4
  key_a_flip = [0]*2
  xored_input_hi = [0]*4
  wr_mac = [0]*4

  
  for i in range(4): 
    ct_lo_flip[i] = bit_rev(ct_lo[3-i],32)
    ct_hi_flip[i] = bit_rev(ct_hi[3-i],32)
  
  for i in range(len(key_a)):
    
    key_a_flip[i] = bit_rev(key_a[1-i],64)
  
  #stage -1
  ghash_lo = ghash(ct_lo_flip, key_a_flip)
  #XOR
  for i in range(4): 
    xored_input_hi[i] =  ct_hi_flip[i] ^ ghash_lo[i]

  #STAGE-2
  ghash_hi = ghash(xored_input_hi, key_a_flip)
  

  for i in range(4): 
    ghash_hi_flip[i] = bit_rev(ghash_hi[3-i],32)
    wr_mac[i] =  data_aes[i] ^ ghash_hi_flip[i]
    # print(hex(wr_mac[i]))


  return wr_mac

def process_chunk(chunk, mode, auth_key, enc_key, iv, address):
    exored_aes = []; wr_mac = [] ; mac_tag = []
    key_a = [0]*2
    ccm_lo_xored = [0]*16
    backend = default_backend()
    # Copy the original IV to ensure it is re-initialized for each chunk
    iv_copy = iv.copy()
    # Region start and region base address needs to be programmed according to mmr
    region_start_addr = 0
    mac_start_addr = 0
    mac_region_offset_addr = (address - (region_start_addr<<12))
    mac_calc_addr = (mac_region_offset_addr>>3) + mac_start_addr
    
    # XOR the IV with the current address
    iv_copy = xor_address_with_iv(iv_copy, address)

    if mode == 'auth':
        cipher = Cipher(algorithms.AES(auth_key), modes.GCM(iv_copy), backend=backend)
        encryptor = cipher.encryptor()
        encryptor.update(chunk)
        encryptor.finalize()
        return chunk, encryptor.tag

    elif mode == 'encrypt':
        chunk=reverse_array(chunk)
        enc_key = reverse_array(enc_key)
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv_copy), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(chunk) + encryptor.finalize()
        ciphertext=reverse_array(ciphertext)
        return ciphertext

    elif mode == 'gcm':
        rev_chunk=reverse_array(chunk)
        rev_enc_key = reverse_array(enc_key)
        cipher = Cipher(algorithms.AES(rev_enc_key), modes.CTR(iv_copy), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(rev_chunk) + encryptor.finalize()
        ciphertext=reverse_array(ciphertext)

        if(address%32==0):
            exored_aes = aes_data_mac(enc_key, iv, mac_calc_addr)
            for i in range(len(exored_aes)//4):
                aes_data[i] = (int.from_bytes(exored_aes[i*4:(4*i)+4], byteorder='little'))
                ct_lo[i] = (int.from_bytes(ciphertext[i*4:(4*i)+4], byteorder='little'))
        else:
            for i in range(len(ciphertext)//4):
                ct_hi[i] = (int.from_bytes(ciphertext[i*4:(4*i)+4], byteorder='little'))
            for i in range(len(auth_key)//8):
                key_a[i] = (int.from_bytes(auth_key[i*8:(8*i)+8], byteorder='little'))
            # wr_mac = gmac(ct_lo, ct_hi, aes_data, key_a)
            # call c_gmac 
            wr_mac = c_gmac.call(ct_lo, ct_hi, aes_data, key_a)

            for i in wr_mac:
                mac_tag.append(i&0xFF)
                mac_tag.append(i>>8&0xFF)
                mac_tag.append(i>>16&0xFF)
                mac_tag.append(i>>24&0xFF)

            mac_tag = bytes(mac_tag)

        return bytes(mac_tag),ciphertext
    
    elif mode == 'ccm':
        rev_chunk=reverse_array(chunk)
        rev_enc_key = reverse_array(enc_key)
        cipher = Cipher(algorithms.AES(rev_enc_key), modes.CTR(iv_copy), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(rev_chunk) + encryptor.finalize()
        ciphertext=reverse_array(ciphertext)

        if(address%32==0):
            ccm_lo_data = cmac(auth_key,ciphertext)
            for i in range(len(ccm_lo_data)):
                ccm_lo[i] = ccm_lo_data[i]

        else:
            for i in range(len(ciphertext)):
               ccm_lo_xored[i] = ccm_lo[i] ^ ciphertext[i]
            mac_tag = cmac(auth_key,bytes(ccm_lo_xored))
        return bytes(mac_tag),ciphertext

    elif mode == 'both':
        chunk=reverse_array(chunk)
        enc_key = reverse_array(enc_key)
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(auth_key)
        ciphertext = encryptor.update(chunk) + encryptor.finalize()
        ciphertext=reverse_array(ciphertext)
        tag=encryptor.tag
        return ciphertext,tag
    else:
        raise ValueError("Invalid mode specified")


def process_file(input_file, output_file, mode, mac_size,start_addr, auth_key, enc_key, iv):
    address = start_addr # Starting address
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
     while True:
        chunk = f_in.read(16)
        if not chunk:
            break
        if len(chunk) < 16:
            chunk = chunk.ljust(16, b'\x00')
        if (mode == 'gcm') or mode =='ccm':
            tag,processed_chunk= process_chunk(chunk, mode, auth_key, enc_key, iv, address)

            if(address%32==0):
                cipher_text = processed_chunk
            else:
                f_out.write(tag[0:int(mac_size)])
                f_out.write(cipher_text)
                f_out.write(processed_chunk)
        else:
            processed_chunk = process_chunk(chunk, mode, auth_key, enc_key, iv, address)
            f_out.write(processed_chunk)
        address += 16 # Increment address by chunk size


def enc_process_data(input_buffer: bytes, mode: str, mac_size: int, start_addr: int, auth_key: bytes, enc_key: bytes, iv: bytes) -> bytes:
    """
    Process a buffer using the given mode, authentication key, encryption key, and initialization vector.

    Args:
    - input_buffer (bytes or bytearray): Input buffer to be processed.
    - mode (str): Mode of operation (e.g., 'gcm').
    - mac_size (int): Size of the authentication tag.
    - start_addr (int): Starting address.
    - auth_key (bytes): Authentication key.
    - enc_key (bytes): Encryption key.
    - iv (bytes): Initialization vector.

    Returns:
    bytes: Processed output buffer.
    """    
    iv = reverse_array(iv)
    address = start_addr  # Starting address
    output_buffer = io.BytesIO()  # Create an in-memory buffer to store output
    input_buffer = io.BytesIO(input_buffer)  # Convert input buffer to BytesIO
    while True:
        chunk = input_buffer.read(16)  # Read 16 bytes at a time
        if not chunk:
            break  # End of buffer reached

        if len(chunk) < 16:
            # Pad the chunk with zeros to make it 16 bytes long
            chunk = chunk.ljust(16, b'\x00')

        if (mode == 'gcm') or (mode =='ccm'):
            # GCM mode: process chunk and write authentication tag and cipher text
            tag, processed_chunk = process_chunk(
                chunk, mode, auth_key, enc_key, iv, address
            )
            # Write authentication tag and cipher text to output buffer
            if (address % 32) == 0:
                # Write cipher text only when address is a multiple of 32
                cipher_text = processed_chunk
            else:
                output_buffer.write(tag[0:int(mac_size)])
                output_buffer.write(cipher_text)
                output_buffer.write(processed_chunk)  # Write processed chunk twice
        else:
            # Non-GCM mode: process chunk and write to output buffer
            processed_chunk = process_chunk(chunk, mode, auth_key, enc_key, iv, address)
            output_buffer.write(processed_chunk)

        address += 16  # Increment address by chunk size

    # Get the output buffer as bytes
    output = output_buffer.getvalue()
    return output


def enc_process_data_na(input_buffer: bytes, mac_size: int) -> bytes:
    CHUNK_SIZE = 32
    output_buffer = io.BytesIO()  # Create an in-memory buffer to store output
    input_buffer = io.BytesIO(input_buffer)  # Convert input buffer to BytesIO
    while True:
        chunk = input_buffer.read(CHUNK_SIZE)  
        if not chunk:
            break  # End of buffer reached
        output_buffer.write(b'\xff'*mac_size)
        output_buffer.write(chunk)

    # Get the output buffer as bytes
    output = output_buffer.getvalue()
    return output


def main():
    parser = argparse.ArgumentParser(description='Process AppImage file with optional GCM and GMAC.')
    parser.add_argument('--input_path', type=str, required=True, help='Path to the input AppImage file')
    parser.add_argument('--output_path', type=str, required=True, help='Path to the output file')
    parser.add_argument('--load_addr', type=str, default='0x00000', help='Flashing Address in hexadecimal format')
    parser.add_argument('--mode', choices=['auth', 'encrypt', 'gcm' , 'ccm', 'both'], required=True, help='Operation mode: auth, encrypt, or both')
    parser.add_argument('--mac_size', type=str, default='16', help='Mac size for authentication(4B, 8B, 12B or 16B)')
    args = parser.parse_args()

    #iv = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # Example IV, you should provide your IV
    iv = bytearray([0x3c, 0x2d, 0x1e, 0x0f, 0x78, 0x69, 0x5a, 0x4b, 0x67, 0x45, 0x23, 0x01, 0xa9, 0xcb, 0xed, 0x8f])
    #encryption_key = bytearray([0x77, 0x6b, 0xef, 0xf2, 0x85, 0x1d, 0xb0, 0x6f, 0x4c, 0x8a, 0x05, 0x42, 0xc8, 0x69, 0x6f, 0x6c, 0x6a, 0x81, 0xaf, 0x1e, 0xec, 0x96, 0xb4, 0xd3, 0x7f, 0xc1, 0xd6, 0x89, 0xe6, 0xc1, 0xc1, 0x04]) # Example encryption key, you should provide your key
    #encryption_key = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8f, 0xed, 0xcb, 0xa9, 0x12, 0x23, 0x45, 0x67, 0x4b, 0x5a, 0x69, 0x78, 0x0f, 0x1e, 0x2d, 0x3c]) # Example encryption key, you should provide your key
    #encryption_key = bytearray([0x3c, 0x2d, 0x1e, 0x0f, 0x78, 0x69, 0x5a, 0x4b, 0x67, 0x45, 0x23, 0x01, 0xa9, 0xcb, 0xed, 0x8f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # Example encryption key, you should provide your key
    encryption_key = bytearray([0x3c, 0x2d, 0x1e, 0x0f, 0x78, 0x69, 0x5a, 0x4b, 0x67, 0x45, 0x23, 0x01, 0xa9, 0xcb, 0xed, 0x8f]) # Example encryption key, you should provide your key
    #print(encryption_key)
    #authentication_key = bytearray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) # Example authentication key, you should provide your key
    authentication_key = bytearray([0x3c, 0x2d, 0x1e, 0x0f, 0x78, 0x69, 0x5a, 0x4b, 0x67, 0x45, 0x23, 0x01, 0xa9, 0xcb, 0xed, 0x8f])
    process_file(args.input_path, args.output_path, args.mode,args.mac_size, int(args.load_addr,16), authentication_key, encryption_key, reverse_array(iv))
    #cmac(authentication_key,ct_lo_dum)

    flash_add = int(args.load_addr, 16) + (int(args.load_addr, 16) // 32) * int(args.mac_size)
    print(f"Needs to be Flashed at flash offset {hex(flash_add)}")


if __name__ == "__main__":
    main()
