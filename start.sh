#!/bin/bash
set -em

python /opt/ocr/ocr.py &
PYTHON_PID=$!

sleep 2

/opt/ocr/ztinfra-enclaveproducedhtml &
RUST_PID=$!

wait -n
exit $?
