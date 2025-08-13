CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS += -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

all: hello.bpf.o getdents_only.bpf.o hello_loader

hello.bpf.o: hello.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c hello.bpf.c -o hello.bpf.o

getdents_only.bpf.o: getdents_only.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c getdents_only.bpf.c -o getdents_only.bpf.o

hello_loader: hello_loader.c
	gcc -o hello_loader hello_loader.c -lbpf

clean:
	rm -f hello.bpf.o getdents_only.bpf.o hello_loader

install-deps:
	sudo apt update
	sudo apt install -y libbpf-dev clang llvm

.PHONY: all clean install-deps
