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