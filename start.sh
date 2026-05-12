#!/bin/bash
set -em

/usr/bin/python3 /opt/ocr/ocr.py &
PYTHON_PID=$!

sleep 2

/opt/ocr/ztinfra-enclaveproducedhtml &
RUST_PID=$!

wait -n
exit $?
