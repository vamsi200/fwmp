BPF_CLANG := clang
BPF_CFLAGS := -g -O2 -target bpf

.PHONY: all clean

all: fwmp.bpf.o

fwmp.bpf.o: fwmp.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f fwmp.bpf.o
