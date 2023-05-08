/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h" // 关于vmlinux头文件定义位置？
// #include <bpf/bpf.h> // 会与vmlinux冲突
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

struct network_message {
	size_t tcp_send_flow;
	size_t tcp_recv_flow;
	size_t udp_send_flow;
	size_t udp_recv_flow;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg,struct sock *sk, struct msghdr *msg, size_t len)
{
	//u16 index = sk->__sk_common.skc_dport;
	u32 index = 0;
	u16 dport = 0; 
	bpf_probe_read_kernel(&dport,sizeof(dport),&(sk->__sk_common.skc_dport));
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_printk("This is Send message PID = %d.len = %d\n", pid,len);

	return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg,struct sock *sk, struct msghdr *msg, size_t len)
{
	//u16 index = sk->__sk_common.skc_dport;
	u32 index = 0;
	u16 dport = 0; 
	bpf_probe_read_kernel(&dport,sizeof(dport),&(sk->__sk_common.skc_dport));
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_printk("This is Recv message PID = %d.len = %d\n", pid,len);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";