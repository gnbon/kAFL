#!/bin/sh
cd ~/kAFL/
python3 kAFL-Fuzzer/kafl_fuzz.py \
	-vm_ram snapshot_win/ \
	-vm_dir snapshot_win/ \
	-agent targets/windows_x86_64/bin/fuzzer/MsIo_test.exe \
	-mem 4096 \
	-seed_dir in/ \
	-work_dir out/ \
	-ip0 0xfffff80204aa0000-0xfffff80204aa8000 \
	-d \
	-v \
	-tui \
	--purge
	
