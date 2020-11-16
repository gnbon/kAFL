import json
import argparse


parser = argparse.ArgumentParser(description='Generate Windows user-land agent with a interface recovery output')
parser.add_argument('filename', help='interface recovery output file (JSON)', type=str)
parser.add_argument('-name', help='driver service name (not required if already in output file)', required=False, type=str)
args = parser.parse_args()

name = args.name

f = open(args.filename, 'r')

json_data = json.load(f)
f.close()

data = ''
num = 0


for json in json_data:
    num += 1
    data += '\t{'
    data += json['IoControlCode']
    data += ','
    
    for inputbuf in json['InputBufferLength'][0].split('-'):
        if inputbuf == 'inf':
            inputbuf = 65535
        data += hex(int(inputbuf))
        data += ','    
    
    outputbuf = json['OutputBufferLength'][0].split('-')[1] 
    if outputbuf == 'inf':
        outputbuf = '65535'
    data += hex(int(outputbuf))
    data += ','    

    data = data[:-1]
    data += '},\n'
data = data[:-2]
print(data)
f = open('./template.c', 'r')
code = f.read()
f.close()

code = code.replace('__CONSTRAINTS__', data)
code = code.replace('__LEN__', str(num))
code = code.replace('__DEVICELINK__', name)

f = open('./agent.c', 'w')
f.write(code)
f.close()

#print(data)
