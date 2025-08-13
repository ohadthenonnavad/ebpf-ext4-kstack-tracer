#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Permit deep stack traces */
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
    /* Optional process-name filter (currently disabled): keep for easy re-enable
     * Uncomment to capture only from "ls" processes.
     */
    // char comm[16];
    // bpf_get_current_comm(&comm, sizeof(comm));
    // if (comm[0] != 'l' || comm[1] != 's' || comm[2] != 0) {
    //     return 0;  // Skip non-ls processes
    // }

    __u32 key = 0;
    struct stack_trace_t *data = bpf_map_lookup_elem(&stackdata_map, &key);
    if (!data) {
        return 0;
    }

    data->pid = bpf_get_current_pid_tgid();
    data->kern_stack_size = bpf_get_stack(ctx, data->kern_stack,
                          MAX_STACK_DEPTH * sizeof(__u64),
                          0);  // 0 for kernel stack

    bpf_perf_event_output(ctx, &perfmap, BPF_F_CURRENT_CPU,
                  data, sizeof(struct stack_trace_t));
    return 0;
}

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

/* Additional ext4 probes for file-related syscalls */
SEC("kprobe/ext4_lookup")
int trace_ext4_lookup(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_file_open")
int trace_ext4_file_open(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_create")
int trace_ext4_create(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_file_read_iter")
int trace_ext4_file_read_iter(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_map_blocks")
int trace_ext4_map_blocks(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_file_write_iter")
int trace_ext4_file_write_iter(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_writepages")
int trace_ext4_writepages(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_sync_file")
int trace_ext4_sync_file(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/jbd2_journal_commit_transaction")
int trace_jbd2_journal_commit_transaction(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_rename")
int trace_ext4_rename(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_unlink")
int trace_ext4_unlink(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_mkdir")
int trace_ext4_mkdir(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_rmdir")
int trace_ext4_rmdir(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_link")
int trace_ext4_link(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_symlink")
int trace_ext4_symlink(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_setattr")
int trace_ext4_setattr(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_getattr")
int trace_ext4_getattr(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_file_mmap")
int trace_ext4_file_mmap(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_fallocate")
int trace_ext4_fallocate(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_get_link")
int trace_ext4_get_link(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_permission")
int trace_ext4_permission(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

/* Generic read path hooks to catch reads across filesystems */
SEC("kprobe/generic_file_read_iter")
int trace_generic_file_read_iter(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/filemap_read")
int trace_filemap_read(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

/* Newer ext4 read helpers (folio-based) */
SEC("kprobe/ext4_read_folio")
int trace_ext4_read_folio(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}

SEC("kprobe/ext4_readahead")
int trace_ext4_readahead(struct pt_regs *ctx)
{
    return handle_stack(ctx);
}
