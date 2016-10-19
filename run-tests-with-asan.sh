#!/bin/sh -e

DEGU_INSTRUMENT_BUILD=true python3.5-dbg setup.py build_ext -i

export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-3.8 
export ASAN_OPTIONS=symbolize=1
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.3.0.0 python3.5-dbg setup.py test --skip-sphinx --skip-flakes
