'''Abstraction layer for parsing arguments'''
import argparse
from collections import namedtuple
from modules import desc

def xip_addr_type(arg_val: str) -> tuple:
    '''Custom type to take xip arguments'''
    parts = arg_val.split(':')
    if len(parts) != 2:
        raise argparse.ArgumentTypeError('Invalid XIP arguments')
    start_addr = 0
    end_addr = 0

    if parts[0].startswith('0x') and parts[1].startswith('0x'):
        start_addr = int(parts[0], 16)
        end_addr = int(parts[1], 16)


    if end_addr <= start_addr:
        raise argparse.ArgumentTypeError('XIP end start address is less than start address')

    addr_range = namedtuple('AddressRange', ['start', 'end'])

    return addr_range(start=start_addr, end=end_addr)

def get_args():
    '''Abstraction layer to fetch arguments via argparse module'''
    my_parser = argparse.ArgumentParser(description=desc.G_TOOL_DEFINITION)
    my_parser.add_argument('-i', '--core-img', required=True, action='append', nargs='*')
    my_parser.add_argument('-s', '--sso', required=False, action='append', nargs='*')
    my_parser.add_argument('-m', '--metadata', required=False)
    my_parser.add_argument('--merge-segments', required=False, default=False, action='store_true')
    my_parser.add_argument('-t', '--tolerance-limit', type=int, required=False, default=0)
    my_parser.add_argument('-o', '--output', required=False, default='multicoreelf.out')
    my_parser.add_argument('--xip', required=False, type=xip_addr_type, default=None)

    return my_parser.parse_args()

if __name__ == "__main__":
    pass
