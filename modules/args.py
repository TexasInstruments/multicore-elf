import argparse
import sys
import os
sys.path.append(os.path.realpath('../'))
from modules import desc

def get_args():
    p = argparse.ArgumentParser(description=desc.G_TOOL_DEFINITION)
    p.add_argument('-i', '--core-img', required=True, action='append', nargs='*')
    p.add_argument('-s', '--sso', required=False, action='append', nargs='*')
    p.add_argument('-m', '--metadata', required=False)
    p.add_argument('--merge-segments', required=False, default=False, action='store_true')
    p.add_argument('-t', '--tolerance-limit', required=False, default=0)
    p.add_argument('-a', '--offset-align', required=False, default=0)
    p.add_argument('-z', '--size-align', required=False, default=0)
    p.add_argument('-o', '--output', required=False, default='multicoreelf.out')

    return p.parse_args()

if __name__ == "__main__":
    pass