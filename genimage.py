import os
from modules.args import get_args
from modules.multicoreelf import MultiCoreELF

def main():
    arguments = get_args()

    M = MultiCoreELF(
        segmerge=arguments.merge_segments, 
        tol_limit=int(arguments.tolerance_limit), 
        ofname=arguments.output,
        )
    
    for ifname in arguments.core_img:
        M.add_elf(os.path.realpath(ifname[0]))

    M.add_metadata(arguments.metadata)

    M.generate_multicoreelf()

if __name__ == "__main__":
    main()