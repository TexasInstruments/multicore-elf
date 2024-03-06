import json

def address_translate(xlat_file_path, coreid, addr):
    output_addr = addr
    with open(xlat_file_path, 'r') as file:
        data = json.load(file)
        
    region_addr_info = list(data['cores'].values())[coreid]['info']

    for info in region_addr_info:
        cpulocaladdr = int(info["cpulocaladdr"], 16)
        socaddr = int(info["socaddr"], 16)
        regionsize = int(info["regionsize"], 16)
        if((addr >= cpulocaladdr) and (addr < cpulocaladdr + regionsize)):
            offset = addr - cpulocaladdr
            output_addr = socaddr + offset
            break

    return output_addr
    