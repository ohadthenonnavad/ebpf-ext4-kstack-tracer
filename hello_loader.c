#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--getdents-only]\n\n"
            "  --getdents-only   Load getdents-only BPF (ext4_dx_readdir, ext4_bread). Default loads full tracer.\n",
            prog);
}

static FILE *g_jsonl = NULL;
static char g_jsonl_path[512] = {0};
static time_t g_jsonl_opened_at = 0; /* epoch seconds when current JSONL was opened */
static char g_out_dir[64] = "events"; /* default output directory */

/* Struct must match BPF side */
#define MAX_STACK_DEPTH 127
struct stack_trace_t {
    int pid;
    int kern_stack_size;
    __u64 kern_stack[MAX_STACK_DEPTH];
};

/* Simple /proc/kallsyms loader and resolver */
struct ksym {
    unsigned long long addr;
    char name[256];
};

static struct ksym *ksyms = NULL;
static size_t ksym_cnt = 0;

static int load_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "[warn] cannot open /proc/kallsyms: %s. Kernel symbolization disabled.\n", strerror(errno));
        return -1;
    }
    size_t cap = 1 << 12; /* start with 4K symbols, grow as needed */
    ksyms = (struct ksym *)malloc(cap * sizeof(struct ksym));
    if (!ksyms) {
        fclose(f);
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long addr;
        char type;
        char name[256];
        if (sscanf(line, "%llx %c %255s", &addr, &type, name) != 3)
            continue;
        if (ksym_cnt == cap) {
            cap *= 2;
            struct ksym *tmp = (struct ksym *)realloc(ksyms, cap * sizeof(struct ksym));
            if (!tmp) {
                free(ksyms);
                ksyms = NULL;
                ksym_cnt = 0;
                fclose(f);
                return -1;
            }
            ksyms = tmp;
        }
        ksyms[ksym_cnt].addr = addr;
        strncpy(ksyms[ksym_cnt].name, name, sizeof(ksyms[ksym_cnt].name) - 1);
        ksyms[ksym_cnt].name[sizeof(ksyms[ksym_cnt].name) - 1] = '\0';
        ksym_cnt++;
    }
    fclose(f);
    if (ksym_cnt == 0) {
        free(ksyms);
        ksyms = NULL;
        return -1;
    }
    /* /proc/kallsyms is typically sorted; if not, we could qsort here. */
    return 0;
}

static const char *resolve_kaddr(unsigned long long addr, unsigned long long *offset)
{
    if (!ksyms || ksym_cnt == 0) {
        if (offset) *offset = 0;
        return NULL;
    }
    /* binary search for rightmost symbol <= addr */
    size_t lo = 0, hi = ksym_cnt;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ksyms[mid].addr <= addr) lo = mid; else hi = mid;
    }
    unsigned long long base = ksyms[lo].addr;
    if (base > addr) {
        if (offset) *offset = 0;
        return NULL;
    }
    if (offset) *offset = addr - base;
    return ksyms[lo].name;
}

/* Format current local time as ISO8601 with microseconds and timezone, e.g., 2025-08-12T14:42:05.123456+03:00 */
static void current_time_iso8601(char *buf, size_t bufsz)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm lt;
    localtime_r(&tv.tv_sec, &lt);
    char tzbuf[8] = {0};
    strftime(tzbuf, sizeof(tzbuf), "%z", &lt); /* e.g., +0300 */
    char tz_formatted[8] = {0};
    if (strlen(tzbuf) == 5) {
        /* insert colon: +0300 -> +03:00 */
        tz_formatted[0] = tzbuf[0];
        tz_formatted[1] = tzbuf[1];
        tz_formatted[2] = tzbuf[2];
        tz_formatted[3] = ':';
        tz_formatted[4] = tzbuf[3];
        tz_formatted[5] = tzbuf[4];
        tz_formatted[6] = '\0';
    } else {
        strncpy(tz_formatted, tzbuf, sizeof(tz_formatted)-1);
    }
    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%dT%H:%M:%S", &lt);
    snprintf(buf, bufsz, "%s.%06ld%s", datebuf, (long)tv.tv_usec, tz_formatted);
}

/* Read short process name (comm) from /proc/<pid>/comm */
static void read_comm_from_proc(int pid, char *buf, size_t bufsz)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        strncpy(buf, "unknown", bufsz - 1);
        buf[bufsz - 1] = '\0';
        return;
    }
    if (!fgets(buf, bufsz, f)) {
        strncpy(buf, "unknown", bufsz - 1);
        buf[bufsz - 1] = '\0';
        fclose(f);
        return;
    }
    fclose(f);
    /* strip trailing newline */
    size_t len = strlen(buf);
    if (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[len - 1] = '\0';
}

/* Write a single event as one-line JSON (JSONL) */
static void open_new_jsonl(void)
{
    char iso_ts[64];
    current_time_iso8601(iso_ts, sizeof(iso_ts));
    for (char *p = iso_ts; *p; ++p) { if (*p == ':' || *p == ' ') *p = '-'; }
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0)
        strncpy(hostname, "unknown", sizeof(hostname)-1);
    snprintf(g_jsonl_path, sizeof(g_jsonl_path), "%s/capture_%s_%s.jsonl", g_out_dir, iso_ts, hostname);
    g_jsonl = fopen(g_jsonl_path, "w");
    if (!g_jsonl) {
        fprintf(stderr, "[warn] cannot open %s for writing: %s\n", g_jsonl_path, strerror(errno));
    } else {
        g_jsonl_opened_at = time(NULL);
        printf("Writing JSONL events to %s\n", g_jsonl_path);
    }
}

static void maybe_rotate_jsonl(void)
{
    time_t now = time(NULL);
    /* rotate every 5 minutes */
    if (g_jsonl && g_jsonl_opened_at + 300 <= now) {
        fclose(g_jsonl);
        g_jsonl = NULL;
        open_new_jsonl();
    }
}

static void write_event_jsonl_line(int cpu, struct stack_trace_t *trace)
{
    maybe_rotate_jsonl();
    if (!g_jsonl) return;
    char iso_ts[64];
    current_time_iso8601(iso_ts, sizeof(iso_ts));

    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0)
        strncpy(hostname, "unknown", sizeof(hostname)-1);

    char comm[64] = {0};
    read_comm_from_proc(trace->pid, comm, sizeof(comm));

    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    if (uname(&uts) != 0) {
        strncpy(uts.release, "unknown", sizeof(uts.release)-1);
    }

    /* Infer probe from top-most frame symbol if available */
    const char *probe = "unknown";
    unsigned long long top_addr = 0, top_off = 0;
    const char *top_name = NULL;
    if (trace->kern_stack_size >= (int)sizeof(__u64)) {
        top_addr = (unsigned long long)trace->kern_stack[0];
        top_name = resolve_kaddr(top_addr, &top_off);
        if (top_name)
            probe = top_name;
    }

    int frames = trace->kern_stack_size / (int)sizeof(__u64);

    /* Start JSON object */
    fprintf(g_jsonl, "{\"timestamp\":\"%s\",\"hostname\":\"%s\",\"kernel_version\":\"%s\",",
            iso_ts, hostname, uts.release);
    fprintf(g_jsonl, "\"ls_pid\":%d,\"comm\":\"%s\",\"probe\":\"%s\",\"cpu\":%d,\"frames\":[",
            trace->pid, comm, probe, cpu);

    for (int i = 0; i < frames; i++) {
        unsigned long long addr = (unsigned long long)trace->kern_stack[i];
        unsigned long long off = 0;
        const char *name = resolve_kaddr(addr, &off);
        if (i) fputc(',', g_jsonl);
        if (name)
            fprintf(g_jsonl, "{\"index\":%d,\"addr\":\"0x%llx\",\"symbol\":\"%s\",\"offset\":\"0x%llx\"}",
                    i, addr, name, off);
        else
            fprintf(g_jsonl, "{\"index\":%d,\"addr\":\"0x%llx\",\"symbol\":null,\"offset\":\"0x%llx\"}",
                    i, addr, off);
    }
    fprintf(g_jsonl, "]}\n");
    fflush(g_jsonl);
}

static void write_event_json(int cpu, struct stack_trace_t *trace)
{
    char iso_ts[64];
    current_time_iso8601(iso_ts, sizeof(iso_ts));

    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname)) != 0)
        strncpy(hostname, "unknown", sizeof(hostname)-1);

    char comm[64] = {0};
    read_comm_from_proc(trace->pid, comm, sizeof(comm));

    struct utsname uts;
    memset(&uts, 0, sizeof(uts));
    if (uname(&uts) != 0) {
        strncpy(uts.release, "unknown", sizeof(uts.release)-1);
    }

    /* Determine probe name as the top-most resolved symbol if available */
    const char *probe = "unknown";
    unsigned long long top_addr = 0, top_off = 0;
    const char *top_name = NULL;
    if (trace->kern_stack_size >= (int)sizeof(__u64)) {
        top_addr = (unsigned long long)trace->kern_stack[0];
        top_name = resolve_kaddr(top_addr, &top_off);
        if (top_name)
            probe = top_name;
    }

    /* Ensure events/ directory exists and build filename: events/event_<ISO8601>_<hostname>.json */
    if (mkdir("events", 0755) != 0 && errno != EEXIST) {
        /* best effort: if cannot create, fall back to current dir */
    }
    char fname[512];
    snprintf(fname, sizeof(fname), "events/event_%s_%s.json", iso_ts, hostname);

    FILE *out = fopen(fname, "w");
    if (!out)
        return;

    int frames = trace->kern_stack_size / (int)sizeof(__u64);

    /* Write JSON */
    fprintf(out, "{\n");
    fprintf(out, "  \"timestamp\": \"%s\",\n", iso_ts);
    fprintf(out, "  \"hostname\": \"%s\",\n", hostname);
    fprintf(out, "  \"kernel_version\": \"%s\",\n", uts.release);
    fprintf(out, "  \"ls_pid\": %d,\n", trace->pid);
    fprintf(out, "  \"comm\": \"%s\",\n", comm);
    fprintf(out, "  \"probe\": \"%s\",\n", probe);
    fprintf(out, "  \"cpu\": %d,\n", cpu);
    fprintf(out, "  \"frames\": [\n");
    for (int i = 0; i < frames; i++) {
        unsigned long long addr = (unsigned long long)trace->kern_stack[i];
        unsigned long long off = 0;
        const char *name = resolve_kaddr(addr, &off);
        fprintf(out, "    { \"index\": %d, \"addr\": \"0x%llx\", ", i, addr);
        if (name)
            fprintf(out, "\"symbol\": \"%s\", \"offset\": \"0x%llx\" }%s\n", name, off, (i + 1 < frames) ? "," : "");
        else
            fprintf(out, "\"symbol\": null, \"offset\": \"0x0\" }%s\n", (i + 1 < frames) ? "," : "");
    }
    fprintf(out, "  ],\n");
    fprintf(out, "  \"stack_text\": [\n");
    for (int i = 0; i < frames; i++) {
        unsigned long long addr = (unsigned long long)trace->kern_stack[i];
        unsigned long long off = 0;
        const char *name = resolve_kaddr(addr, &off);
        if (name)
            fprintf(out, "    \"0x%llx %s+0x%llx\"%s\n", addr, name, off, (i + 1 < frames) ? "," : "");
        else
            fprintf(out, "    \"0x%llx\"%s\n", addr, (i + 1 < frames) ? "," : "");
    }
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
    fclose(out);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct stack_trace_t *trace = (struct stack_trace_t *)data;
    int frames = trace->kern_stack_size / (int)sizeof(__u64);
    printf("\n[stack] PID %d, frames %d (kernel)\n", trace->pid, frames);
    for (int i = 0; i < frames; i++) {
        unsigned long long addr = (unsigned long long)trace->kern_stack[i];
        unsigned long long off = 0;
        const char *name = resolve_kaddr(addr, &off);
        if (name)
            printf("  %p %s+0x%llx\n", (void*)addr, name, (unsigned long long)off);
        else
            printf("  %p\n", (void*)addr);
    }
    fflush(stdout);

    /* Append JSONL line to the capture file */
    write_event_jsonl_line(cpu, trace);
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "[warn] lost %llu events on CPU %d\n",
            (unsigned long long)lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    struct bpf_link *link = NULL;
    struct bpf_program *prog;
    struct bpf_object *obj;
    int err;
    const char *obj_path = "hello.bpf.o"; /* default: full tracer */
    bool getdents_only = false;

    /* Parse minimal flags */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--getdents-only") == 0) {
            obj_path = "getdents_only.bpf.o";
            getdents_only = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
    if (err) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 1;
    }

    /* Open BPF application */
    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file '%s' failed\n", obj_path);
        return 1;
    }

    /* Optionally resize perfmap to number of CPUs before loading */
    struct bpf_map *perf_map = bpf_object__find_map_by_name(obj, "perfmap");
    if (!perf_map) {
        fprintf(stderr, "ERROR: finding perfmap failed\n");
        goto cleanup;
    }
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus > 0)
        bpf_map__set_max_entries(perf_map, (unsigned int)ncpus);

    /* Load & verify BPF programs */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    /* Attach all BPF programs found in the object */
    struct bpf_program *p;
    struct bpf_link *links[32];
    size_t link_cnt = 0;
    memset(links, 0, sizeof(links));
    bpf_object__for_each_program(p, obj) {
        if (link_cnt >= (sizeof(links)/sizeof(links[0]))) {
            fprintf(stderr, "ERROR: too many programs to attach\n");
            goto cleanup;
        }
        struct bpf_link *l = bpf_program__attach(p);
        int aerr = libbpf_get_error(l);
        if (aerr) {
            if (aerr == -ENOENT || aerr == -ESRCH) {
                fprintf(stderr, "[info] skipping attach for %s: symbol not found (%d)\n", bpf_program__name(p), aerr);
                continue;
            }
            fprintf(stderr, "ERROR: bpf_program__attach failed for %s: %s (%d)\n", bpf_program__name(p), strerror(-aerr), aerr);
            goto cleanup;
        }
        links[link_cnt++] = l;
    }

    /* No stack_traces map in this program; using perfmap + per-CPU scratch map in BPF side */

    /* Already attached programs above */

    /* Set up perf buffer to read stack events */
    int map_fd = bpf_map__fd(perf_map);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: getting perf map fd: %s\n", strerror(errno));
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    struct perf_buffer *pb = perf_buffer__new(map_fd, 8 /*pages*/, handle_event, handle_lost, NULL, NULL);
    err = libbpf_get_error(pb);
    if (err) {
        fprintf(stderr, "ERROR: creating perf buffer: %s\n", strerror(-err));
        pb = NULL;
        goto cleanup;
    }

    /* Try to load kernel symbols for symbolization */
    if (load_kallsyms() == 0) {
        printf("Loaded %zu kernel symbols from /proc/kallsyms.\n", ksym_cnt);
    } else {
        printf("Kernel symbolization unavailable (try 'sudo sysctl -w kernel.kptr_restrict=0').\n");
    }

    /* Prepare JSONL capture file */
    strncpy(g_out_dir, getdents_only ? "events/score" : "events", sizeof(g_out_dir)-1);
    g_out_dir[sizeof(g_out_dir)-1] = '\0';
    if (mkdir("events", 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[warn] failed to create events/ directory: %s\n", strerror(errno));
    }
    if (getdents_only) {
        if (mkdir("events/score", 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[warn] failed to create events/score directory: %s\n", strerror(errno));
        }
    }
    open_new_jsonl();

    printf("eBPF program attached. Reading kernel stack traces. Press Ctrl+C to stop.\n");
    while (!exiting) {
        int ret = perf_buffer__poll(pb, 1000);
        if (ret < 0 && ret != -EINTR) {
            fprintf(stderr, "ERROR: perf_buffer__poll: %d\n", ret);
            break;
        }
    }

cleanup:
    if (link)
        bpf_link__destroy(link);
    for (size_t i = 0; i < link_cnt; i++)
        bpf_link__destroy(links[i]);
    /* Free perf buffer if created (safe to call with NULL) */
    perf_buffer__free(pb);
    bpf_object__close(obj);
    if (g_jsonl) {
        fclose(g_jsonl);
        g_jsonl = NULL;
    }
    return 0;
}
