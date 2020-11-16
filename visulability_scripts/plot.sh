#!/bin/sh

var="$1.dot"

echo "파일 이름은 "${var}" 입니다."

python3 ~/kAFL/kAFL-Fuzzer/kafl_plot.py ~/kAFL/out/ ~/"${var}"
xdot ~/"${var}"
