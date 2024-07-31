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

    m_elf.generate_multicoreelf(max_segment_size=arguments.max_segment_size,
                                segmerge=arguments.merge_segments,
                                tol_limit=arguments.tolerance_limit,
                                ignore_context=arguments.ignore_context,
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
