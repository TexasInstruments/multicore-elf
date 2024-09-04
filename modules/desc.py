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

'''Descriptions module'''

G_TOOL_DEFINITION = '''
This image creation tool takes multiple ELF files supposed to be loaded into different CPUs of an SOC and combines them 
into one single ELF image with merged segments. There is also an option to specify the metadata which will go in as a note 
segment.
'''
# ARGS
G_ARG_IMAGE_DEFINITION = '''
This argument is used to specify the individual ELF images to be combined into the final image
'''
G_ARG_SSO_DEFINITION = '''
This argument is used to specify the static shared objects to be combined into the final image
'''
G_ARG_TOL_LIMIT_DEFINITION = '''
This argument is used to specify the tolerance limit in bytes when combining segments.
'''
G_OUT_IMAGE_DEFINITION = '''
This argument is used to specify the output file name.
'''
G_METADATA_DEFINITION = '''
This argument is used to specify metadata file.
'''

if __name__ == "__main__":
    pass
