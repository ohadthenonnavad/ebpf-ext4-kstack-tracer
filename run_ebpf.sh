#!/bin/bash

# eBPF Getdents Automation Script
# This script automatically runs the getdents eBPF program and monitors output

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup on exit
cleanup() {
    print_info "Cleaning up..."
    
    # Kill the loader if it's running
    if [ ! -z "$LOADER_PID" ]; then
        print_info "Stopping eBPF loader (PID: $LOADER_PID)..."
        kill $LOADER_PID 2>/dev/null || true
        wait $LOADER_PID 2>/dev/null || true
    fi
    
    # Kill the trace monitor if it's running
    if [ ! -z "$TRACE_PID" ]; then
        print_info "Stopping trace monitor (PID: $TRACE_PID)..."
        kill $TRACE_PID 2>/dev/null || true
        wait $TRACE_PID 2>/dev/null || true
    fi
    
    # Kill the perf event reader if it's running
    if [ ! -z "$PERF_READER_PID" ]; then
        print_info "Stopping perf event reader (PID: $PERF_READER_PID)..."
        kill $PERF_READER_PID 2>/dev/null || true
        wait $PERF_READER_PID 2>/dev/null || true
    fi
    
    print_success "Cleanup complete!"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    print_info "Usage: sudo ./run_ebpf.sh"
    exit 1
fi

# Check if the eBPF program is built
if [ ! -f "hello.bpf.o" ] || [ ! -f "hello_loader" ]; then
    print_warning "eBPF program not built. Building now..."
    make
    print_success "Build complete!"
fi

print_info "Starting eBPF getdents kernel stack tracing demo (ls only)..."
print_info "Press Ctrl+C to stop the program"
echo

# Clear the trace buffer
echo > /sys/kernel/debug/tracing/trace

# Start the eBPF loader in the background (prints stack traces)
print_info "Starting eBPF loader..."
./hello_loader &
LOADER_PID=$!

# Give the loader time to attach
sleep 2

# Check if the loader is still running
if ! kill -0 $LOADER_PID 2>/dev/null; then
    print_error "eBPF loader failed to start!"
    exit 1
fi

print_success "eBPF program loaded and attached!"

# Start monitoring the trace output
print_info "Loader will print kernel stack traces here when ls triggers getdents."

:

# Generate some activity to trigger the eBPF program
print_info "Generating directory listing activity to trigger eBPF program..."
sleep 1

# Create some directory listing operations to trigger our eBPF program
(
    sleep 2
    echo -e "\n${YELLOW}[DEMO]${NC} Creating directory listing operations to trigger eBPF program..."
    ls /tmp > /dev/null 2>&1
    ls /home > /dev/null 2>&1
    ls /etc > /dev/null 2>&1
    echo -e "${YELLOW}[DEMO]${NC} Directory operations complete. You should see eBPF messages above!"
    echo -e "${YELLOW}[DEMO]${NC} Try running 'ls' commands in another terminal to see more messages."
    echo -e "${YELLOW}[DEMO]${NC} Press Ctrl+C to stop the program."
) &

# Wait for user to stop the program
wait $TRACE_PID
