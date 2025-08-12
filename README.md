# eBPF Hello World Program (getdents)

This is a "Hello World" program written in eBPF that demonstrates directory listing monitoring on Linux using the `getdents64` system call.

## What it does

The program attaches to the `sys_enter_getdents64` tracepoint and captures kernel stack traces when `ls` processes list directory contents. The stack traces are sent to user-space via perf events.

## Features

- Captures user-space stack traces for ls processes
- Filters out all other processes
- Stores stack traces for later analysis

## Prerequisites

- Linux kernel with eBPF support (kernel 5.8+ recommended for full stack trace functionality, note that kernel 4.18+ is the minimum required for basic functionality)
- libbpf development library
- clang compiler
- Root privileges (for loading eBPF programs)

## Installation

1. Install dependencies:
```bash
make install-deps
```

2. Build the program:
```bash
make
```

## Running the program

1. Start the eBPF program (requires root):
```bash
sudo ./run_ebpf.sh
```

2. The script will automatically:
   - Load the eBPF program
   - Monitor trace output
   - Generate demo directory listing operations
   - Filter for getdents messages

3. You should see stack traces in the output

4. Try running `ls` commands in another terminal to see more stack traces

## Files

- `hello.bpf.c` - The eBPF kernel program (getdents version)
- `hello_loader.c` - User-space loader program
- `Makefile` - Build configuration
- `run_ebpf.sh` - Automation script
- `README.md` - This file

## Stopping the program

Press **Ctrl+C** in the terminal running the script to stop the program and clean up.

## How it works

1. The eBPF program attaches to the `sys_enter_getdents64` tracepoint
2. Every time an `ls` process lists directory contents, our eBPF function runs
3. The stack trace appears in the output
4. The automation script handles building, loading, monitoring, and cleanup
