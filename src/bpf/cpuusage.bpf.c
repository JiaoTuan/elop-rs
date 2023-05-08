/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h" // 关于vmlinux头文件定义位置？
// #include <bpf/bpf.h> // 会与vmlinux冲突
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct switch_args {
	unsigned long long ignore;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};

struct key_k {
	uint32_t pid;
	uint32_t cpu;
};

struct val_k {
	uint64_t total;
	uint64_t idle;
	uint64_t last_time;
	uint64_t cpu;
};
const volatile int i = 0;
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct key_k);
	__type(value, __u64);
} pid_start SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct key_k);
	__type(value, __u64);
} idle_start SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct val_k);
} cpu_info_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u32);
} cpu_lastpid_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} extime_map SEC(".maps");
SEC("tracepoint/sched/sched_switch")
int tracepoint_sched_switch(struct switch_args *args)
{
    struct task_struct *parent_struct;
    // 1. 打时间戳
    uint64_t ts = bpf_ktime_get_ns();
    struct key_k key_prev, key_next;
	struct val_k *val, value;
	uint64_t delta_total, delta_idle;
	uint64_t *tsp_p, *tsp_i;
	uint32_t prev_pid, next_pid, cpu, extime_key = 0;
    // 2. 获取到了上一个进程的pid和下一个要切换进程的pid 与当前cpu编号
    prev_pid = key_prev.pid = args->prev_pid;
    next_pid = key_next.pid = args->next_pid;;
    cpu = key_prev.cpu = key_next.cpu = bpf_get_smp_processor_id();
    // 3. 查询使用key_prev查询上一次的时间戳 并对其进行判断
    tsp_p = bpf_map_lookup_elem(&pid_start,&key_prev);
    if(tsp_p){
        // 上次任务执行时间
        delta_total = ts - (*tsp_p);
		delta_idle = 0;
        // 找到了上次任务的时间戳 并且使用了 那就删除
        bpf_map_delete_elem(&pid_start,&key_prev);
        // 查询idle进程
        tsp_i = bpf_map_lookup_elem(&idle_start,&key_prev);
        if (tsp_i) {
			delta_idle = ts - (*tsp_i);
			bpf_map_delete_elem(&idle_start,&key_prev);
		}
        val = bpf_map_lookup_elem(&cpu_info_map,&cpu);
        if(val){
            value = (*val);
        }else {
            value.total = 0;
            value.idle = 0;
        }
        value.total += delta_total;
		value.idle += delta_idle;
		value.last_time = ts;
		value.cpu = cpu;
        bpf_map_update_elem(&cpu_info_map,&cpu,&value,BPF_ANY);
    }
    bpf_map_update_elem(&pid_start,&key_next,&ts,BPF_ANY);
    if (next_pid == 0) {
		bpf_map_update_elem(&idle_start,&key_next,&ts,BPF_ANY);
	}
    // bpf_map_update_elem(&cpu_lastpid_map,&cpu,&next_pid,BPF_ANY);
    // bpf_map_update_elem(&extime_map,&extime_key,&ts,BPF_ANY);
	// bpf_printk("cpu = %d usage = %d\n", cpu,value.total-value.idle);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";