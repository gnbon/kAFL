#!/usr/bin/python3
import os
import sys
import time
import argparse
import subprocess

# initialize argument parser
parser = argparse.ArgumentParser(description='Get Windows driver base address and patch QEMU code.')
parser.add_argument('name', help='device or symlink name', type=str)
args = parser.parse_args()

os.chdir("/home/user/kAFL")
# disassembler.c file path
SRC = './qemu-5.0.0/pt/disassembler.c'

# driver service name - should be configured before run
SVCNAME = args.name.encode()

# original driver base address
orig = 0

# open source code and find previous driver base address
with open(SRC, 'r') as f:
    res = f.read()
    idx = res.find('cofi.target_addr |=')
    res = res[idx + 20:idx + 38]
    orig = int(res, 16)

# run info binary to get new base address 
res = subprocess.check_output([
    './kAFL-Fuzzer/kafl_info.py',
    '-vm_dir', './snapshot_win/',
    '-vm_ram', './snapshot_win/',
    '-agent', './targets/windows_x86_64/bin/info/info.exe',
    '-mem', '4096',
    '-v',
    '-work_dir', './out/'
])
idx = res.find(SVCNAME)
if idx == -1:
    print('Could not find the service name!')
    sys.exit(0)
res = res[:idx - 1]
endaddr = int(res[-18:], 16)
startaddr = int(res[-37:-19], 16)
kbase = (endaddr & 0xFFFFFFFF00000000)

# print startaddr and endaddr
print(f'[+] startaddr: {hex(startaddr)}')
print(f'[+] endaddr: {hex(endaddr)}')
time.sleep(2)

# patch the source code
if orig != kbase:
    f = open(SRC, 'r')
    src = f.read()
    f.close()
    src = src.replace('|= ' + hex(orig), '|= ' + hex(kbase))
    f = open(SRC, 'w')
    f.write(src)
    f.close()

    # recompie qemu-5.0.0
    popen = subprocess.Popen(['./install.sh', 'qemu'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     universal_newlines=True)
    for line in iter(popen.stdout.readline, ''):
        print(line, end='')
    popen.stdout.close()

# write wfuzz.sh
script = '#!/bin/sh\n'
script += 'cd ~/kAFL/\n'
script += 'python3 kAFL-Fuzzer/kafl_fuzz.py \\\n'
script += '\t-vm_ram snapshot_win/ \\\n'
script += '\t-vm_dir snapshot_win/ \\\n'
script += '\t-agent targets/windows_x86_64/bin/fuzzer/bruteforce_test.exe \\\n'
script += '\t-mem 4096 \\\n'
script += '\t-seed_dir in/ \\\n'
script += '\t-work_dir out/ \\\n'
script += '\t-ip0 {}-{} \\\n'.format(hex(startaddr), hex(endaddr))
script += '\t-d \\\n'
script += '\t-v \\\n'
script += '\t--purge'
script += '\n'

f = open('./wfuzz.sh', 'w')
f.write(script)
f.close()
