'''Main script to generate the multicore ELF image'''
from modules.args import get_args
from modules.multicoreelf import MultiCoreELF
from modules.note import CustomNote

def generate_image(arguments, m_elf: MultiCoreELF, custom_note: CustomNote = None):
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
    m_elf.generate_multicoreelf(segmerge=segment_merge_flag,
                                tol_limit=arguments.tolerance_limit,
                                ignore_context=ignore_context_flag,
                                xlat_file_path=arguments.xlat,
                                custom_note=custom_note)

def main():
    '''Main function'''
    arguments = get_args()

    if arguments.xlat is not None and arguments.xlat.strip() == "":
        arguments.xlat = None

    is_xip = bool(arguments.xip is not None)

    ignore_range = None
    accept_range = None

    if is_xip:
        ignore_range = accept_range = arguments.xip

        m_elf_xip = MultiCoreELF(
            ofname=f"{arguments.output}_xip",
            accept_range=accept_range
            )
        generate_image(arguments, m_elf_xip)

    m_elf = MultiCoreELF(
        ofname=arguments.output,
        ignore_range=ignore_range
        )
    generate_image(arguments, m_elf)

if __name__ == "__main__":
    main()
