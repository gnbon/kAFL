import json
import argparse

parser = argparse.ArgumentParser(description='Generate Windows user-land agent with a interface recovery output')
parser.add_argument('--json', help='interface recovery output file (JSON)', type=str)
parser.add_argument('--svcname', help='driver service name (not required if already in output file)', required=False, type=str)
parser.add_argument('--svcpath', help='driver service path (not required if already in output file)', required=False, type=str)
args = parser.parse_args()

svcName = args.svcname
svcPath = args.svcpath.replace("\\", "\\\\")

f = open(args.json, 'r')

json_data = json.load(f)
f.close()

interfaces = ''
num = 0

for json in json_data:
    interfaces += '\t{'
    interfaces += json['IoControlCode']
    interfaces += ', '

    in_buf_range = json['InputBufferLength'][0].split('-')
    in_buf_min = in_buf_range[0]
    in_buf_max = in_buf_range[1]
    if bool(in_buf_min == in_buf_max) == True:
        is_static = 'true'
    else:
        is_static = 'false'

    if in_buf_max == 'inf': 
        in_buf_max = 0xff # TODO determine inf size
    interfaces += hex(int(in_buf_max))
    interfaces += ', '

    out_buf_size =  json['OutputBufferLength'][0].split('-')[1]
    if out_buf_size == 'inf': 
        out_buf_size = 0xffff # TODO determine inf size
    interfaces += hex(int(out_buf_size))
    interfaces += ', '

    payload = 'NULL'
    interfaces += payload
    interfaces += ', '

    interfaces += str(is_static)

    interfaces += '},\n'
interfaces = interfaces[:-2]

with open('./template.c', 'r') as f:
    templateCode = f.read()

templateCode = templateCode.replace('__INTERFACE__', interfaces)
templateCode = templateCode.replace('__SVC_NAME__', svcName)
replaceCode = templateCode.replace('__SVC_PATH__', svcPath)

with open('./agent.c', 'w') as f:
    f.write(replaceCode)