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

'''Append ECC bytes'''

import os
import argparse
import struct

MAX_SIZE = 103

# Function to generate ECC
def ecc_gen(lbit):

    ecc0 = lbit[0] ^ lbit[1] ^ lbit[2] ^ lbit[4] ^ lbit[5] ^ lbit[7] ^ lbit[10] ^ lbit[11] ^ lbit[12] ^ lbit[14] ^ lbit[17] ^ lbit[18] ^ lbit[21] ^ lbit[23] ^ lbit[24] ^ lbit[26] ^ lbit[27] ^ lbit[29] ^ lbit[32] ^ lbit[33] ^ lbit[36] ^ lbit[38] ^ lbit[39] ^ lbit[41] ^ lbit[44] ^ lbit[46] ^ lbit[47] ^ lbit[50] ^ lbit[51] ^ lbit[53] ^ lbit[56] ^ lbit[57] ^ lbit[58] ^ lbit[60] ^ lbit[63] ^ lbit[64] ^ lbit[67] ^ lbit[69] ^ lbit[70] ^ lbit[72] ^ lbit[75] ^ lbit[77] ^ lbit[78] ^ lbit[81] ^ lbit[82] ^ lbit[84] ^ lbit[87] ^ lbit[88] ^ lbit[91] ^ lbit[93] ^ lbit[94] ^ lbit[97] ^ lbit[98] ^ lbit[100]

    ecc1 = lbit[0] ^ lbit[1] ^ lbit[3] ^ lbit[4] ^ lbit[6] ^ lbit[8] ^ lbit[10] ^ lbit[11] ^ lbit[13] ^ lbit[15] ^ lbit[17] ^ lbit[19] ^ lbit[21] ^ lbit[23] ^ lbit[25] ^ lbit[26] ^ lbit[28] ^ lbit[30] ^ lbit[32] ^ lbit[34] ^ lbit[36] ^ lbit[38] ^ lbit[40] ^ lbit[42] ^ lbit[44] ^ lbit[46] ^ lbit[48] ^ lbit[50] ^ lbit[52] ^ lbit[54] ^ lbit[56] ^ lbit[57] ^ lbit[59] ^ lbit[61] ^ lbit[63] ^ lbit[65] ^ lbit[67] ^ lbit[69] ^ lbit[71] ^ lbit[73] ^ lbit[75] ^ lbit[77] ^ lbit[79] ^ lbit[81] ^ lbit[83] ^ lbit[85] ^ lbit[87] ^ lbit[89] ^ lbit[91] ^ lbit[93] ^ lbit[95] ^ lbit[97] ^ lbit[99] ^ lbit[101]

    ecc2 = lbit[0] ^ lbit[2] ^ lbit[3] ^ lbit[5] ^ lbit[6] ^ lbit[9] ^ lbit[10] ^ lbit[12] ^ lbit[13] ^ lbit[16] ^ lbit[17] ^ lbit[20] ^ lbit[21] ^ lbit[24] ^ lbit[25] ^ lbit[27] ^ lbit[28] ^ lbit[31] ^ lbit[32] ^ lbit[35] ^ lbit[36] ^ lbit[39] ^ lbit[40] ^ lbit[43] ^ lbit[44] ^ lbit[47] ^ lbit[48] ^ lbit[51] ^ lbit[52] ^ lbit[55] ^ lbit[56] ^ lbit[58] ^ lbit[59] ^ lbit[62] ^ lbit[63] ^ lbit[66] ^ lbit[67] ^ lbit[70] ^ lbit[71] ^ lbit[74] ^ lbit[75] ^ lbit[78] ^ lbit[79] ^ lbit[82] ^ lbit[83] ^ lbit[86] ^ lbit[87] ^ lbit[90] ^ lbit[91] ^ lbit[94] ^ lbit[95] ^ lbit[98] ^ lbit[99] ^ lbit[102]

    ecc3 = lbit[1] ^ lbit[2] ^ lbit[3] ^ lbit[7] ^ lbit[8] ^ lbit[9] ^ lbit[10] ^ lbit[14] ^ lbit[15] ^ lbit[16] ^ lbit[17] ^ lbit[22] ^ lbit[23] ^ lbit[24] ^ lbit[25] ^ lbit[29] ^ lbit[30] ^ lbit[31] ^ lbit[32] ^ lbit[37] ^ lbit[38] ^ lbit[39] ^ lbit[40] ^ lbit[45] ^ lbit[46] ^ lbit[47] ^ lbit[48] ^ lbit[53] ^ lbit[54] ^ lbit[55] ^ lbit[56] ^ lbit[60] ^ lbit[61] ^ lbit[62] ^ lbit[63] ^ lbit[68] ^ lbit[69] ^ lbit[70] ^ lbit[71] ^ lbit[76] ^ lbit[77] ^ lbit[78] ^ lbit[79] ^ lbit[84] ^ lbit[85] ^ lbit[86] ^ lbit[87] ^ lbit[92] ^ lbit[93] ^ lbit[94] ^ lbit[95] ^ lbit[100] ^ lbit[101] ^ lbit[102]

    ecc4 = lbit[4] ^ lbit[5] ^ lbit[6] ^ lbit[7] ^ lbit[8] ^ lbit[9] ^ lbit[10] ^ lbit[18] ^ lbit[19] ^ lbit[20] ^ lbit[21] ^ lbit[22] ^ lbit[23] ^ lbit[24] ^ lbit[25] ^ lbit[33] ^ lbit[34] ^ lbit[35] ^ lbit[36] ^ lbit[37] ^ lbit[38] ^ lbit[39] ^ lbit[40] ^ lbit[49] ^ lbit[50] ^ lbit[51] ^ lbit[52] ^ lbit[53] ^ lbit[54] ^ lbit[55] ^ lbit[56] ^ lbit[64] ^ lbit[65] ^ lbit[66] ^ lbit[67] ^ lbit[68] ^ lbit[69] ^ lbit[70] ^ lbit[71] ^ lbit[80] ^ lbit[81] ^ lbit[82] ^ lbit[83] ^ lbit[84] ^ lbit[85] ^ lbit[86] ^ lbit[87] ^ lbit[96] ^ lbit[97] ^ lbit[98] ^ lbit[99] ^ lbit[100] ^ lbit[101] ^ lbit[102]
    ecc5 = lbit[11] ^ lbit[12] ^ lbit[13] ^ lbit[14] ^ lbit[15] ^ lbit[16] ^ lbit[17] ^ lbit[18] ^ lbit[19] ^ lbit[20] ^ lbit[21] ^ lbit[22] ^ lbit[23] ^ lbit[24] ^ lbit[25] ^ lbit[41] ^ lbit[42] ^ lbit[43] ^ lbit[44] ^ lbit[45] ^ lbit[46] ^ lbit[47] ^ lbit[48] ^ lbit[49] ^ lbit[50] ^ lbit[51] ^ lbit[52] ^ lbit[53] ^ lbit[54] ^ lbit[55] ^ lbit[56] ^ lbit[72] ^ lbit[73] ^ lbit[74] ^ lbit[75] ^ lbit[76] ^ lbit[77] ^ lbit[78] ^ lbit[79] ^ lbit[80] ^ lbit[81] ^ lbit[82] ^ lbit[83] ^ lbit[84] ^ lbit[85] ^ lbit[86] ^ lbit[87]
    ecc6 = lbit[26] ^ lbit[27] ^ lbit[28] ^ lbit[29] ^ lbit[30] ^ lbit[31] ^ lbit[32] ^ lbit[33] ^ lbit[34] ^ lbit[35] ^ lbit[36] ^ lbit[37] ^ lbit[38] ^ lbit[39] ^ lbit[40] ^ lbit[41] ^ lbit[42] ^ lbit[43] ^ lbit[44] ^ lbit[45] ^ lbit[46] ^ lbit[47] ^ lbit[48] ^ lbit[49] ^ lbit[50] ^ lbit[51] ^ lbit[52] ^ lbit[53] ^ lbit[54] ^ lbit[55] ^ lbit[56] ^ lbit[88] ^ lbit[89] ^ lbit[90] ^ lbit[91] ^ lbit[92] ^ lbit[93] ^ lbit[94] ^ lbit[95] ^ lbit[96] ^ lbit[97] ^ lbit[98] ^ lbit[99] ^ lbit[100] ^ lbit[101] ^ lbit[102]
    ecc7 = lbit[57] ^ lbit[58] ^ lbit[59] ^ lbit[60] ^ lbit[61] ^ lbit[62] ^ lbit[63] ^ lbit[64] ^ lbit[65] ^ lbit[66] ^ lbit[67] ^ lbit[68] ^ lbit[69] ^ lbit[70] ^ lbit[71] ^ lbit[72] ^ lbit[73] ^ lbit[74] ^ lbit[75] ^ lbit[76] ^ lbit[77] ^ lbit[78] ^ lbit[79] ^ lbit[80] ^ lbit[81] ^ lbit[82] ^ lbit[83] ^ lbit[84] ^ lbit[85] ^ lbit[86] ^ lbit[87] ^ lbit[88] ^ lbit[89] ^ lbit[90] ^ lbit[91] ^ lbit[92] ^ lbit[93] ^ lbit[94] ^ lbit[95] ^ lbit[96] ^ lbit[97] ^ lbit[98] ^ lbit[99] ^ lbit[100] ^ lbit[101] ^ lbit[102]

    binword1 = (ecc3 << 3) | (ecc2 << 2) | (ecc1 << 1) | ecc0
    binword2 = (ecc7 << 3) | (ecc6 << 2) | (ecc5 << 1) | ecc4

    return (binword2 << 4) | binword1

# Function to convert bytes to bits
def convert_bytes_to_bits(bytes_data):
    bits = []
    for byte in bytes_data:
        for j in range(8):
            bits.append((byte >> (7 - j)) & 1)
    return bits


def generate_ecc_for_chunk(bytes_chunk):
    if len(bytes_chunk) < 32:
        bytes_chunk += bytes([0] * (32 - len(bytes_chunk)))

    # ECC P1 calculation
    comb1 = bytes_chunk[7::-1] # Combine bytes 0 to 7
    comb2 = bytes_chunk[11:7:-1] # Combine bytes 8 to 11
    comb_b1_bits = convert_bytes_to_bits(comb1)
    comb_b2_bits = convert_bytes_to_bits(comb2)
    comb_b3_bits = convert_bytes_to_bits([bytes_chunk[12]])[1:] # Use byte 12 and remove the MSB

    final_arr = comb_b3_bits + comb_b2_bits + comb_b1_bits
    final_arr.reverse()

    ecc_p1 = ecc_gen(final_arr)

    # ECC P2 calculation
    comb_b4_bits = convert_bytes_to_bits([bytes_chunk[12]])[:1] # Use MSB of byte 12
    comb5 = bytes_chunk[20:12:-1] # Combine bytes 13 to 20
    comb_b5_bits = convert_bytes_to_bits(comb5)
    comb6 = bytes_chunk[24:20:-1] # Combine bytes 21 to 24
    comb_b6_bits = convert_bytes_to_bits(comb6)
    comb_b7_bits = convert_bytes_to_bits([bytes_chunk[25]])[2:] # Use byte 25 and remove the 2 MSBs

    final_arr = comb_b7_bits + comb_b6_bits + comb_b5_bits + comb_b4_bits
    final_arr.reverse()

    ecc_p2 = ecc_gen(final_arr)

    # ECC P3 calculation
    comb_b8_bits = convert_bytes_to_bits([bytes_chunk[25]])[:2] # Use byte 25 and keep the 2 least significant bits
    comb9 = bytes([0, 0] + list(bytes_chunk[31:25:-1])) # Combine bytes 26 to 31 with two leading zeros
    comb_b9_bits = convert_bytes_to_bits(comb9)
    comb10 = bytes([0, 0, 0, 0]) # Four zero bytes
    comb_b10_bits = convert_bytes_to_bits(comb10)
    comb_b11_bits = convert_bytes_to_bits([0])[3:] # One zero byte and remove

    final_arr = comb_b11_bits + comb_b10_bits + comb_b9_bits + comb_b8_bits
    final_arr.reverse()

    ecc_p3 = ecc_gen(final_arr)

    ecc_p4 = 0 # ECC P4 is 0 as specified

    return (ecc_p1, ecc_p2, ecc_p3, ecc_p4)

# Function to append ECC to output buffer
def append_ecc(input_buffer):
    output_buffer = bytearray()
    input_index = 0
    sizet = len(input_buffer)

    while input_index < sizet:
        bytes_chunk = input_buffer[input_index:input_index + 32]

        ecc_p1, ecc_p2, ecc_p3, ecc_p4 = generate_ecc_for_chunk(bytes_chunk)

        # Append ECC to the block and write to output buffer
        output_buffer.extend(bytes_chunk)
        output_buffer.extend(struct.pack('>B', ecc_p1)) # ECC P1
        output_buffer.extend(struct.pack('>B', ecc_p2)) # ECC P2
        output_buffer.extend(struct.pack('>B', ecc_p3)) # ECC P3
        output_buffer.extend(struct.pack('>B', ecc_p4)) # ECC P4

        input_index += 32

    return output_buffer

def process_file(input_filepath, output_filepath):
    with open(input_filepath, 'rb') as infile:
        input_buffer = infile.read()

    output_buffer = append_ecc(input_buffer)

    with open(output_filepath, 'wb') as outfile:
        outfile.write(output_buffer)


def main():
    parser = argparse.ArgumentParser(description='Append ECC to blocks of a file.')
    parser.add_argument('--input_path', type=str, help='Path to the input .AppImage file')
    parser.add_argument('--output_path', type=str, help='Path to the output file with CRCs appended')
    parser.add_argument('--load_addr', type=str,default='0x80000',help='Flashing Address in hexadecimal format')
    args = parser.parse_args()
    process_file(args.input_path, args.output_path)
    flash_add = int(args.load_addr, 16) + (int(args.load_addr, 16) / 32) * 4
    flash_add = int(flash_add)
    print(f"Needs to be Flashed at flash offset {hex(flash_add)}")

if __name__ == "__main__":
   main()