# MultiCore ELF Generator Tool

Takes multiple ELF files as input and combines their segments to create a minimal single ELF file with ELF header, program header table, custom note segment and the data segments.

### Prerequisites

Install the required libraries to your system specified in `requirements.txt` by:

```
pip install -r requirements.txt
```

### Script arguments

1. --core-img : Path to individual binaries of each core. It is a mandatory argument. Input is given in this format - 
	```
	--core-img=0:<core0_binary.out> --core-img=1:<core1_binary.out>
	```

2. --output : The output file name. It is a mandatory argument.
	```
	--output=<filename>.mcelf
	```

3. --merge-segments : Enable merging segments based on a tolerance limit. Default value is false.

4. --tolerance-limit : The maximum difference (in bytes) between the end address of previous segment and start address of current segment for merging the segments. Default value is zero.

5. --ignore-context : Enable merging of segments that are of different cores. Default value is false.

6. --xip : XIP section's start and end address seperated by a colon. It creates a new file <filename>.mcelf_xip. It is a mandatory argument. In case of no XIP regions, use --xip=None (XIP is disabled even though file exists). Argument format when XIP region exists:
	```
	--xip=0x60100000:0x60200000
	```

7. --xlat : SOC specific Address Translation. SOC JSON located in devideData/AddrTranslate folder. Default value is 'None'. (UNDER DEVELOPMENT, RESERVED FOR FUTURE USE)
	```
	--xlat=deviceData/AddrTranslate/am263xjson
	```

8. --sso : Shared static objects. (UNDER DEVELOPMENT)

9. --max_segment_size : Maximum allowed size of a loadable segment. This feature can only be used with merge_segments disabled. Default values is 8192 bytes.

10. --otfaConfigFile : Path to JSON file containing the OTFA config. Disabled by default with value None.


### MCUSDK integration

- The script should be cloned inside {MCU_SDK_PATH}/tools/boot path.

- genimage.py script called in makefile of all examples and tests. It generates a .mcelf image for all the projects.

- Macros for arguments 3-8 are defined in devconfig/devconfig.mak file.

## Compiling C code 

The assumption here is that gcc is used to compile the code on windows and linux. 

`imports.mak` is the file where compiler path has been set. 
By default it uses the compiler that is on the path of the machine.

It is important to compile the c code by both 32bit and 64bit compiler. If not done, then 32bit python will not be able to call c code.

Use the following command to compile the gmac code:
	```
	gmake -C .\c_modules\gmac\ 
	```

On windows, Download 64bit mingw-gcc from: https://winlibs.com (version >= 14.2.0). For 32bit version of mingw-gcc can be downloaded from https://sourceforge.net/projects/mingw/ (version >= 6.3.0)

On Linux, gcc is already installed and hence no need to download and install it. 