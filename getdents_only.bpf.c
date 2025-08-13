#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_STACK_DEPTH 127

struct stack_trace_t {
    int pid;
    int kern_stack_size;
    __u64 kern_stack[MAX_STACK_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 0);
} perfmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct stack_trace_t));
    __uint(max_entries, 1);
} stackdata_map SEC(".maps");

static __always_inline int handle_stack(struct pt_regs *ctx)
{
    __u32 key = 0;
    struct stack_trace_t *data = bpf_map_lookup_elem(&stackdata_map, &key);
    if (!data) {
        return 0;
    }
    data->pid = bpf_get_current_pid_tgid();
    data->kern_stack_size = bpf_get_stack(ctx, data->kern_stack,
                          MAX_STACK_DEPTH * sizeof(__u64),
                          0);
    bpf_perf_event_output(ctx, &perfmap, BPF_F_CURRENT_CPU,
                  data, sizeof(struct stack_trace_t));
    return 0;
}

/* getdents-related ext4 probes */
SEC("kprobe/ext4_dx_readdir")
int trace_getdents_ext4_dx_readdir(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_bread")
int trace_ext4_bread(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}
