# MultiCore ELF Generator Tool

Takes multiple ELF files as input and combines their segments to create a minimal single ELF file with ELF header, program header table, custom note segment and the data segments.

### Prerequisites

Install the following packages in your system -

```
pip install pyelftools
pip install construct
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

6. --xip : XIP section's start and end address seperated by a colon. It creates a new file <filename>.mcelf_xip. Default value is 'none' (XIP is disabled). To enable XIP creation:
	```
	--xip=0x60100000:0x60200000
	```

7. --xlat : SOC specific Address Translation. SOC JSON located in devideData/AddrTranslate folder. Default value is "" (empty string).
	```
	--xlat=deviceData/AddrTranslate/am263xjson
	```

8. --sso : Shared static objects. YET TO BE IMPLEMENTED.


### MCUSDK integration

- The script should be cloned inside {MCU_SDK_PATH}/tools/boot path.

- genimage.py script called in makefile of all examples and tests. It generates a .mcelf image for all the projects.

- Macros for arguments 3-7 are defined in devconfig/devconfig.mak file.