#!/bin/bash

DIR=$(git rev-parse --show-toplevel)

echo "[INFO] Building bpf object file"
cd "$DIR/bpf" && make

echo "[INFO] Building C3 code and Running"
cd "$DIR" && sudo c3c run
