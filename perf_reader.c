#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <perf-sys.h>
#include <string.h>
#include <errno.h>

// Include the same struct definition as in the eBPF program
#define MAX_STACK_DEPTH 50

struct stack_trace_t {
	int pid;
	int kern_stack_size;
	__u64 kern_stack[MAX_STACK_DEPTH];
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
	struct stack_trace_t *trace = (struct stack_trace_t *)data;
	
	printf("Captured kernel stack trace for PID: %d\n", trace->pid);
	printf("Kernel stack size: %d\n", trace->kern_stack_size);
	
	// Print the kernel stack addresses
	printf("Kernel Stack Trace:\n");
	for (int i = 0; i < trace->kern_stack_size / sizeof(__u64); i++) {
		printf("  %#llx\n", trace->kern_stack[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)	
{
	struct perf_buffer *pb = NULL;
	int map_fd, err;

	libbpf_set_print(libbpf_print_fn);

	map_fd = bpf_obj_get("/sys/fs/bpf/perfmap");
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: opening perf map: %s\n", strerror(errno));
		return 1;
	}

	pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "ERROR: creating perf buffer: %s\n", strerror(-err));
		close(map_fd);
		return 1;
	}

	printf("Perf event reader running. Press Ctrl+C to exit.\n");
	
	while ((err = perf_buffer__poll(pb, 1000)) >= 0) {
		// Continue polling
	}

	perf_buffer__free(pb);
	close(map_fd);
	return 0;
}
