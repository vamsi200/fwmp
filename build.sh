#!/bin/bash

DIR=$(git rev-parse --show-toplevel)

echo "[INFO] Building bpf object file and moving it to resources dir"
cd "$DIR/bpf" && make
cd "$DIR/bpf" && mv fwmp.bpf.o "$DIR/resources"

echo "[INFO] Building C3 code and Running"
cd "$DIR" && sudo c3c run
