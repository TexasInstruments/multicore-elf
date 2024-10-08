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

'''Abstraction layer for parsing arguments'''
import argparse
from collections import namedtuple
from modules import desc

def xip_addr_type(arg_val: str) -> tuple:
    '''Custom type to take xip arguments'''

    if arg_val == 'none' or arg_val == 'None':
        return None

    parts = arg_val.split(':')
    if len(parts) != 2:
        raise argparse.ArgumentTypeError('Invalid XIP arguments')
    start_addr = 0
    end_addr = 0

    if parts[0].startswith('0x') and parts[1].startswith('0x'):
        start_addr = int(parts[0], 16)
        end_addr = int(parts[1], 16)

    if end_addr <= start_addr:
        raise argparse.ArgumentTypeError('XIP end address is less than start address')

    addr_range = namedtuple('AddressRange', ['start', 'end'])

    return addr_range(start=start_addr, end=end_addr)

def get_args():
    '''Abstraction layer to fetch arguments via argparse module'''
    my_parser = argparse.ArgumentParser(description=desc.G_TOOL_DEFINITION)
    my_parser.add_argument('-i', '--core-img', required=True, action='append', nargs='*', \
                           help='Specify the individual ELF images. \
                            To be specified as core_num:ELF_image. \
                                Example: --core-img=0:core0_binary.out')
    my_parser.add_argument('-s', '--sso', required=False, action='append', nargs='*')
    my_parser.add_argument('--merge-segments', required=True, type=str, default=False)
    my_parser.add_argument('-t', '--tolerance-limit', type=int, required=True, default=0)
    my_parser.add_argument('--ignore-context', required=True, type=str, default=False)
    my_parser.add_argument('-o', '--output', required=True, type=str)
    my_parser.add_argument('--xip', required=True, type=xip_addr_type, default=None,\
                           help='Provide the start and end address seperated by colon. \
                            This will generate {multicore_elf.out_xip}. \
                                Example: --xip=0x60100000:0x60200000')
    my_parser.add_argument('--xlat', required=True, type=str, default=None, \
                           help="Path to device JSON file inside the \
                            deviceData/AddrTranslate folder")
    my_parser.add_argument('--max_segment_size', required=True, type=int, default=None, \
                           help="Maximum allowed size for a loadable segment. \
                             This option is not honored when merge segments is set to True")

    return my_parser.parse_args()

if __name__ == "__main__":
    pass
