/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h" // 关于vmlinux头文件定义位置？
// #include <bpf/bpf.h> // 会与vmlinux冲突
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
typedef unsigned int u32;
typedef int pid_t;

struct tcp_idx {
	__u32 saddr;
	__u32 daddr;
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack;
};
struct ip_idx{
    __u32 saddr;
    __u32 daddr;
};
struct tcp_seqack{
    __u32 seq;
    __u32 ack;
};

struct nfs_rpc_headers{
    __u32 fragment_header;
    __u32 XID;
    __u32 msg_type;
    __u32 rpc_version;
    __u32 prog;
    __u32 prog_v;
    __u32 procedure;
};
struct nfs_rpc_cred{
    __u32 flavor;
    __u32 len;
};

struct nfs_rpc_verifier{
    __u32 flavor;
    __u32 len;
};
enum nfs_prog_version{
    nfs2 = 2,
    nfs3 = 3,
    nfs4 = 4,
};

struct esnfs_cache_key {
    __u32 crc_32;
    enum nfs_prog_version progVersion;
    union {
        enum nfsd_procedures2 procedures2;
        enum nfsd_procedures3 procedures3;
        enum nfsd_procedures4 procedures4;
    };
};
struct esnfs_cache_entry {
    struct bpf_spin_lock_t lock;
    int len;
    char valid;
    int hash;
    enum nfsd_procedures3 p3;
    __u8 data[MAX_CACHE_DATA_SIZE];
};
enum nfsd_procedures3{
    nfs3_NULL = 0,
    nfs3_GETATTR = 1,
    nfs3_SETATTR = 2,
    nfs3_LOOKUP = 3,
    nfs3_ACCESS = 4,
    nfs3_READLINK = 5,
    nfs3_READ = 6,
    nfs3_WRITE = 7,
    nfs3_CREATE = 8,
    nfs3_MKDIR = 9,
    nfs3_SYMLINK = 10,
    nfs3_MKNOD = 11,
    nfs3_REMOVE = 12,
    nfs3_RMDIR = 13,
    nfs3_RENAME = 14,
    nfs3_LINK = 15,
    nfs3_READDIR = 16,
    nfs3_READDIRPLUS = 17,
    nfs3_FSSTAT = 18,
    nfs3_FSINFO = 19,
    nfs3_PATHCONF = 20,
    nfs3_COMMIT = 21,
    nfs3_NULLTMP = 22,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_idx));
    __uint(value_size, sizeof(struct tcp_seqack));
    __uint(max_entries,MAX_TCP_ENTRY);
}recv_tx_seqack_num SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_idx));
    __uint(value_size, sizeof(struct tcp_seqack));
    __uint(max_entries, MAX_TCP_ENTRY);
}send_tx_seqack_num SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_idx));
    __uint(value_size, sizeof(struct tcp_seqack));
    __uint(max_entries, MAX_TCP_ENTRY);
}drop_tx_seqack_num SEC(".maps");

// 记录不同版本nfs 目前xid到多少了
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(enum nfs_prog_version));
    __uint(max_entries, 1024 * 256);
} XID_nfsVer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(enum nfsd_procedures3));
    __uint(max_entries, 1024);
} v3_XID_procedures SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024 * 256);
} XID_crc32 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(unsigned int));
    __uint(value_size, sizeof(__be16));
    __uint(max_entries, 1);
} tcp_window_now SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct esnfs_cache_key));
    __uint(value_size, sizeof(struct esnfs_cache_entry));
    __uint(max_entries, 1024);
} map_kcache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_idx));
    __uint(value_size, sizeof(struct tcp_seqack));
    __uint(max_entries,MAX_TCP_ENTRY);
}recv_tx_seqack_num SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct tcp_idx));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_TCP_ENTRY);
}send_tx_XID SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ip_idx));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_TCP_ENTRY);
}recv_tx_XID_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct ip_idx));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_TCP_ENTRY);
}send_tx_XID_ip SEC(".maps");


static __always_inline __u32 crc32_reverse(__u8 *nfs_payload,int len, void* data_end){
    __u8 data;
    __u32 crc = 0xffffffff;						//初始值
#pragma clang loop unroll(disable)
    for (int i = 0; i < 512; i++) {
        if(nfs_payload +1>data_end)
            break;
        __u8 tmp = *nfs_payload;
        data = tmp;			//是否反转
        crc = crc ^ data;

    for (int bit = 0; bit < 8; ++bit) {
        if(crc & 0x00000001)
            crc = (crc >> 1) ^ 0xedb88320;
        else{
            crc >>= 1;
        }
    }
    if(nfs_payload +1>data_end)
        break;
    nfs_payload++;
	}
    return  crc ^ 0xffffffff;
}
static __always_inline void ipv4_l4_csum(void *data_start, __u64 *csum, struct iphdr *iph, void *data_end) {
    int tcplen = __bpf_ntohs(iph->tot_len) - iph->ihl * 4;
    __u32 data_size = (__u32) tcplen;

    __u32 tmp = 0;

    *csum += ((u64) ((__bpf_htonl(iph->saddr) >> 16) & 0xffff) + (u64) (__bpf_htonl(iph->saddr) & 0xffff));

    *csum += ((u64) ((__bpf_htonl(iph->daddr) >> 16) & 0xffff) + (u64) (__bpf_htonl(iph->daddr) & 0xffff));

    tmp = (__u32) (iph->protocol);
    *csum += tmp;
    tmp = (__u32) (data_size);
    *csum += tmp;

    // Compute checksum from scratch by a bounded loop
    __u16 *buf = data_start;
    __u16 readtmp = 0;
    bpf_probe_read_kernel(&readtmp, sizeof(u16), buf);
    for (int i = 0; i < MAX_TCP_LENGTH; i += 2) {

        if ((void *) (buf + 3) > data_end) {

            *csum += __bpf_htons(*buf);
            break;
        }
        if ((void *) (buf + 1) > data_end) {
            break;
        }
        *csum += __bpf_htons(*buf);
        buf++;
    }
    if ((void *) buf + 1 <= data_end) {
        buf++;
        *csum += __bpf_htons(*buf);

    }
    *csum = csum_fold_helper((u32) *csum);
}

static __always_inline int reply_nfs(struct xdp_md *ctx,struct esnfs_cache_entry cacheKey){
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void *) (long) ctx->data;
	struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);

	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct nfs_rpc_headers) >
        data_end) {
        return XDP_PASS;
    }
	unsigned int zero = 0;
    __be16 *tcp_window = bpf_map_lookup_elem(&tcp_window_now, &zero);
	if (!tcp_window)
        return XDP_PASS;

	struct nfs_rpc_headers *rpch = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    __u8 *nfs_payload = (__u8 *) rpch;
    //store length of nfs packet
    __u32 nfs_len_origin = data_end - (void *) rpch;
    //store XID of nfs packet
    __u32 XID_origin = rpch->XID;

	struct esnfs_cache_key cache_key = cacheKey;
    struct esnfs_cache_entry *cache = bpf_map_lookup_elem(&map_kcache, &cache_key);
	
	struct tcp_idx tcpIdx = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
            .source = tcp->source,
            .dest = tcp->dest
    };
    struct ip_idx ipIdx = {
            .saddr = ip->saddr,
            .daddr = ip->daddr,
    };
	struct tcp_seqack *RecvSeqack = bpf_map_lookup_elem(&recv_tx_seqack_num,&tcpIdx);
	// no cache
	if((!cache)||(cache_key.crc_32 == 0)){
        if(RecvSeqack){
            //需要代理，更新待发送的ack、seq to tx_filter
//            struct tcp_seqack *sendSeqack = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
            __be32 temp_seq = tcp->seq;
            struct tcp_seqack SendSeqack_t = {
                    .seq = tcp->ack_seq,
                    .ack = __bpf_htonl(__bpf_htonl(temp_seq) + nfs_len_origin),
            };

            bpf_map_update_elem(&send_tx_XID,&tcpIdx,&XID_origin,BPF_ANY);
            bpf_map_update_elem(&send_tx_XID_ip,&ipIdx,&XID_origin,BPF_ANY);
            if(0 != bpf_map_update_elem(&send_tx_seqack_num,&tcpIdx,&SendSeqack_t,BPF_ANY)){
                return XDP_PASS;
            }
            __u16 source = tcp->source;
            /******************修改tcp信息,seq,ack,XID***************/
            __u32 *XID_recv = bpf_map_lookup_elem(&recv_tx_XID,&tcpIdx);
            if(!XID_recv){
                return XDP_PASS;
            }
            tcp->seq = RecvSeqack->seq;
            tcp->ack_seq = RecvSeqack->ack;
            rpch->XID = *XID_recv;
            __u64 checksum = 0;
            tcp->check = 0;
            ipv4_l4_csum((void *) tcp, &checksum, ip, data_end);
            tcp->check = (__u16)__bpf_htons(checksum);
            /******************修改tcp信息***************/
        }
        return XDP_PASS;
    }else {
		if(cache->p3 != cache_key.procedures3){
            if(RecvSeqack){
                //需要代理，更新待发送的ack,seq,XID to tx_filter
//            struct tcp_seqack *sendSeqack = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
                __be32 temp_seq = tcp->seq;
                struct tcp_seqack SendSeqack_t = {
                        .seq = tcp->ack_seq,
                        .ack = __bpf_htonl(__bpf_htonl(temp_seq) + nfs_len_origin),
                };

                bpf_map_update_elem(&send_tx_XID,&tcpIdx,&XID_origin,BPF_ANY);
                bpf_map_update_elem(&send_tx_XID_ip,&ipIdx,&XID_origin,BPF_ANY);
                if(0 != bpf_map_update_elem(&send_tx_seqack_num,&tcpIdx,&SendSeqack_t,BPF_ANY)){
                    return XDP_PASS;
                }
                __u16 source = tcp->source;
                /******************修改tcp信息,seq,ack,XID***************/
                __u32 *XID_recv = bpf_map_lookup_elem(&recv_tx_XID,&tcpIdx);
                if(!XID_recv){
                    return XDP_PASS;
                }
                tcp->seq = RecvSeqack->seq;
                tcp->ack_seq = RecvSeqack->ack;
                rpch->XID = *XID_recv;

                __u64 checksum = 0;
                tcp->check = 0;
                ipv4_l4_csum((void *) tcp, &checksum, ip, data_end);
                tcp->check = (__u16)__bpf_htons(checksum);

                /******************修改tcp信息***************/
            }
            return XDP_PASS;
			if(!RecvSeqack){
            /******************第一次干扰连接，存储seq、ack信息***************/
            struct tcp_seqack RecvSeqack_t = {
                    .seq = tcp->seq,
                    .ack = tcp->ack_seq
            };
            long ret = bpf_map_update_elem(&recv_tx_seqack_num,&tcpIdx,&RecvSeqack_t,BPF_NOEXIST);

            /******************第一次干扰连接，存储XID信息***************/
            bpf_map_update_elem(&recv_tx_XID,&tcpIdx,&XID_origin,BPF_NOEXIST);
            bpf_map_update_elem(&recv_tx_XID_ip,&ipIdx,&XID_origin,BPF_NOEXIST);
            bpf_map_update_elem(&ip_tcp_map,&ipIdx,&tcpIdx,BPF_NOEXIST);

            __u16 source = tcp->source;
            bpf_printk("first irritate ,ip.src = %x,seq = %u, ack = %u", __bpf_htonl(tcpIdx.saddr), __bpf_htonl(RecvSeqack_t.seq), __bpf_htonl(RecvSeqack_t.ack));

        } else{
            //需要代理，更新待发送的ack,seq,XID to tx_filter
//            struct tcp_seqack *sendSeqack = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
            __be32 temp_seq = tcp->seq;
            struct tcp_seqack SendSeqack_t = {
                    .seq = tcp->ack_seq,
                    .ack = __bpf_htonl(__bpf_htonl(temp_seq) + nfs_len_origin),
            };

            bpf_map_update_elem(&send_tx_XID,&tcpIdx,&XID_origin,BPF_ANY);
            bpf_map_update_elem(&send_tx_XID_ip,&ipIdx,&XID_origin,BPF_ANY);
            if(0 != bpf_map_update_elem(&send_tx_seqack_num,&tcpIdx,&SendSeqack_t,BPF_ANY)){
                // 空 更新失败
                return XDP_PASS;
            }
            //完成代理
//            tcp->seq = RecvSeqack->seq;
//            tcp->ack_seq = RecvSeqack->ack;
        }
	}
	// cache无效
    if (cache->valid == 0)
        return XDP_PASS;
	// cache有效
    //edit length of XDP packet
    int offset = cache->len - nfs_len_origin;

    long adjust_ret = bpf_xdp_adjust_tail(ctx, offset);

    if (adjust_ret != 0)
        return XDP_PASS;
    data_end = (void *) (long) ctx->data_end;
    data = (void *) (long) ctx->data;
    eth = data;
    ip = data + sizeof(*eth);
    ipv6 = data + sizeof(*eth);
    // struct icmphdr_common *icmphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // 解析NFS协议
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct nfs_rpc_headers) >
        data_end) {
        return XDP_PASS;
    }

    rpch = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    /********** 按原路返回 ************/

    /********** eth的修改 **********/
    // 互换eth的源目的地址
    __u8 temp_eth[ETH_ALEN];
    memcpy(temp_eth, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, temp_eth, ETH_ALEN);

    /********** IP的修改 **********/
    // 互换IP的源目的地址
    __be32 temp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = temp;


    /********** tcp的修改 **********/
    // 互换source和dest端口
    __be16 temp_port;
    temp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = temp_port;

    // 将acknumber 放到sequence中
    __be32 temp_seq = tcp->seq;
    tcp->seq = tcp->ack_seq;
    tcp->ack_seq = __bpf_htonl(__bpf_htonl(temp_seq) + nfs_len_origin);


    if (*tcp_window != 0)
        tcp->window = *tcp_window;

    nfs_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
//    start copy cache to xdp packet
#pragma clang loop unroll(disable)
    for (int i = 0; i < (cache->len) && i < MAX_CACHE_DATA_SIZE; ++i) {
        if ((void *) nfs_payload + 1 > data_end)
            break;
        *nfs_payload = cache->data[i];
        nfs_payload++;
    }

    //change ip length
    ip->tot_len = __bpf_htons(data_end - (void *) ip);

    ip->ttl = 64;
    ip->check = 0;
    __u16 ip_check = update_ip_checksum(ip);

    ip->check = __bpf_htons(ip_check);

    // 解析NFS协议
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) +
        sizeof(struct nfs_rpc_reply_headers) > data_end) {
        return XDP_PASS;
    }
    struct nfs_rpc_reply_headers *rpch_reply =
            data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    rpch_reply->XID = XID_origin;


    __u32 payload_len = data_end - (void *) rpch_reply;


    __u64 checksum = 0;
////                bpf_printk("before checksum:%x", __bpf_htons(tcp->check));
//    bpf_printk("checksum before:%x,seq =%u,ack %u", __bpf_htons(tcp->check), __bpf_htonl(tcp->seq), __bpf_htonl(tcp->ack_seq));
    tcp->check = 0;
    ipv4_l4_csum((void *) tcp, &checksum, ip, data_end);
    tcp->check = (u16)__bpf_htons(checksum);
    /********** 将client未来将会发来的ACK包DROP掉，防止出现DUP ACK error **********/
    struct tcp_seqack dropSeqAck = {
            .seq = tcp->ack_seq,
            .ack = __bpf_htonl(payload_len+ __bpf_htonl(tcp->seq))
    };
    long ret = bpf_map_update_elem(&drop_tx_seqack_num,&tcpIdx,&dropSeqAck,BPF_ANY);
//    bpf_printk("drop packet , seq = %u ,ack = %u, ip.saddr = %x",__bpf_htonl(dropSeqAck.seq)
//               ,__bpf_htonl(dropSeqAck.ack), __bpf_htonl(tcpIdx.saddr));
//
//    bpf_printk("tx success..,XID:%x", __bpf_htonl(XID_origin));

    struct audit_nfs_data *event = bpf_ringbuf_reserve(&nfs_audit_events,sizeof (struct audit_nfs_data),BPF_ANY);
    if(!event)
        return XDP_TX;
    //ip addr
    event->saddr = ip->saddr;
    event->daddr = ip->daddr;
    event->source = tcp->source;
    event->dest = tcp->dest;
    event->prog_v = nfs3;
    event->XID = __bpf_htonl(rpch_reply->XID);
    event->procedures3 = cacheKey.procedures3;
    bpf_ringbuf_submit(event,BPF_ANY);

    return XDP_TX;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{   
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
	if (ip + 1 > data_end)
        return XDP_PASS;
	void *trans = data + sizeof(*eth) + sizeof(*ip);
	struct udphdr *udp;
	struct tcphdr *tcp;
	__be16 dport;
	switch (ip->protocol)
	{
	case IPPROTO_UDP:
		udp = (struct udphdr *) trans;
		if (udp + 1 > data_end)
            return XDP_PASS;
		dport = udp->dest;
		payload = transp + sizeof(struct udphdr);
		if (dport == bpf_htonl(1024)){
			
		}
		break;
	case IPPROTO_TCP:
		tcp = (struct tcphdr *) transp;
        if (tcp + 1 > data_end) {
            return XDP_PASS;
        }
        dport = tcp->dest;
        payload = transp + sizeof(struct tcphdr);
        if (dport == bpf_htonl(1024)) {
			struct tcp_idx tcpIdx = {
				.saddr = ip->saddr,
				.daddr = ip->daddr,
				.source = tcp->source,
				.dest = tcp->dest
			};
			struct tcp_seqack *RecvSeqack = bpf_map_lookup_elem(&recv_tx_seqack_num,&tcpIdx);
			if( __bpf_htons(ip->tot_len) == sizeof (struct iphdr)+sizeof(struct tcphdr))
            {
                if(RecvSeqack){
					// bpf_printk("recv detected , ip.saddr = %x,seq = %u ,ack = %u", __bpf_htonl(tcpIdx.saddr),__bpf_htonl(tcp->seq),__bpf_htonl(tcp->ack_seq));
					struct tcp_seqack *dropSeqAck = bpf_map_lookup_elem(&drop_tx_seqack_num,&tcpIdx);
					// 第一遍为空 不进入这里
					if(dropSeqAck){
						//bpf_printk("DROP FIND ,seq = %u ack = %u", __bpf_htonl(dropSeqAck->seq),__bpf_htonl(dropSeqAck->ack));
						if(tcp->ack == 1 && tcp->rst ==0 && tcp->fin == 0 && tcp->psh ==0){
							if(dropSeqAck->seq == tcp->seq && dropSeqAck->ack == tcp->ack_seq){
							// bpf_printk("DROP EXISTED ,seq = %u ack = %u", __bpf_htonl(dropSeqAck->seq),
							//__bpf_htonl(dropSeqAck->ack));
								if(0 == bpf_map_delete_elem(&drop_tx_seqack_num,&tcpIdx)){
									return XDP_DROP;
								}
							}
						}
					}
					//需要代理，更新待发送的ack、seq to tx_filter
					//struct tcp_seqack *sendSeqack = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
					__be32 temp_seq = tcp->seq;
					struct tcp_seqack SendSeqack_t = {
							.seq = tcp->ack_seq,
							.ack = temp_seq,
					};
//                        if(0 != bpf_map_update_elem(&send_tx_seqack_num,&tcpIdx,&SendSeqack_t,BPF_ANY)){
//                            return XDP_PASS;
//                        }
					__u16 source = tcp->source;
					/******************修改tcp信息***************/
					__u32 temp_seqt = __bpf_htonl(tcp->seq);
//                        bpf_printk("no payload,need recv ,seq before %u ,seq now %u ",temp_seqt, __bpf_htonl(RecvSeqack->seq));
					tcp->seq = RecvSeqack->seq;
					tcp->ack_seq = RecvSeqack->ack;
					__u64 checksum = 0;
					tcp->check = 0;
					ipv4_l4_csum((void *) tcp, &checksum, ip, data_end);
					tcp->check = (u16)__bpf_htons(checksum);

					/******************修改tcp信息***************/
				}
                return XDP_PASS;
            }
			// tcphdr len > 20 , have options，直接PASS 记录下来
			if((tcp->doff)*4 != 20){
				__u32 ip_saddr = ip->saddr;
				__u32 ip_daddr = ip->daddr;
				__u32 tcp_source = tcp->source;
				__u32 tcp_dest = tcp->dest;
				int offset = sizeof(*eth) + sizeof(*ip)+(tcp->doff)*4;
				bpf_xdp_adjust_head(ctx, offset);
				void *newpayload = (void *) (long) ctx->data;
				void *data_end = (void *) (long) ctx->data_end;
				struct nfs_rpc_headers *rpch;
				rpch = (struct nfs_rpc_headers *) newpayload;
				if (rpch + 1 > data_end)
					return XDP_PASS;

				if (__bpf_htonl(rpch->prog) != nfs_rpc_prog)
				{
					bpf_printk("prog type = %x, nfs_rpc_prog = %u",__bpf_htonl(rpch->prog),nfs_rpc_prog);
					//identify rpc
					return XDP_PASS;
				}
				__u32 nfs_v = __bpf_htonl(rpch->prog_v);
				if (nfs_v <= 1 || nfs_v >= 5)
					return XDP_PASS;
				enum nfs_prog_version prog_v = nfs_v;
				if (prog_v == nfs3){
					enum nfsd_procedures3 p3 = __bpf_htonl(rpch->procedure);
					struct audit_nfs_data *event = bpf_ringbuf_reserve(&nfs_audit_events,sizeof (struct audit_nfs_data),BPF_ANY);
					if(!event)
						break;
					//ip addr
					event->saddr = ip_saddr;
					event->daddr = ip_daddr;
					event->source = tcp_source;
					event->dest = tcp_dest;
					event->prog_v = prog_v;
					event->XID = __bpf_htonl(rpch->XID);
					event->procedures3 = p3;
					bpf_ringbuf_submit(event,BPF_ANY);
				}
				bpf_xdp_adjust_head(ctx,-offset);
				return XDP_PASS;
			}
			
			bpf_printk("size of tcphdr:%d,len of tcp :%d",sizeof(struct tcphdr),(tcp->doff)*4);
			struct nfs_rpc_headers *rpch;
			rpch = (struct nfs_rpc_headers) payload;
			if (rpch + 1 > data_end)
                return XDP_PASS;
			bpf_printk("ip->frag_off: %x",ip->frag_off);
			//verify the rpc program type 100003服务历程 就是说这是read write等一系列操作 放行其他两种类型nfs操作集
			if (__bpf_htonl(rpch->prog) != 100003)
			{
				bpf_printk("prog type = %x, nfs_rpc_prog = 100003",__bpf_htonl(rpch->prog));
				//identify rpc
				return XDP_PASS;
			}
			__u32 nfs_v = __bpf_htonl(rpch->prog_v);
			if (nfs_v <= 1 || nfs_v >= 5)
                return XDP_PASS;
			enum nfs_prog_version prog_v = nfs_v;
            __u32 XID = __bpf_htonl(rpch->XID);
			long xidret = bpf_map_update_elem(&XID_nfsVer, &XID, &prog_v, BPF_ANY);
			bpf_printk("nfs call,xidret = %d",xidret);
			if (xidret != 0)
				return XDP_PASS;
			switch (prog_v) {
				case nfs2: {
					break;
				}
				case nfs3: {
					// 具体操作函数
					enum nfsd_procedures3 p3 = __bpf_htonl(rpch->procedure);
					__u32 saddr = ip->saddr;
					//记录该次数据访问的XID对应的procedure
					bpf_map_update_elem(&v3_XID_procedures, &XID, &p3, BPF_ANY);
					__u32 crc_32 = 0;
					switch (p3) {
						case nfs3_NULL: {
							break;
						}
						case nfs3_LOOKUP: 
						case nfs3_FSSTAT:
						case nfs3_READDIRPLUS:
						case nfs3_READDIR:
						case nfs3_READ:
						case nfs3_GETATTR: {
							// if you need fragment then do not process bit2表示不分片
							if(ip->frag_off != 0x40)
								break;
							// 判断rpc数据包是否有payload
							if ((void *) rpch + sizeof(struct nfs_rpc_headers) + sizeof(struct nfs_rpc_cred) + 1 >
								data_end)
								break;
							// nfs_auth_info RPC证书
							struct nfs_rpc_cred *cred = (void *) rpch + sizeof(struct nfs_rpc_headers);
							__u32 cred_len = __bpf_htonl(cred->len);

							int offset = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(*rpch) + sizeof(*cred) +
											cred_len;
							// bpf_printk("offset = %d", offset);
							if (0 == bpf_xdp_adjust_head(ctx, offset)) {
								void *newpayload = (void *) (long) ctx->data;
								void *data_end = (void *) (long) ctx->data_end;
								bpf_printk("data_end - newpayload = %d", data_end - newpayload);
								struct nfs_rpc_verifier *verifier = newpayload;
								if ((void *) verifier + sizeof(struct nfs_rpc_verifier) > data_end)
									return XDP_PASS;
								
								__u32 ver_len = __bpf_htonl(verifier->len);
								int offset_v = sizeof(*verifier) + ver_len;
								bpf_printk("offset_v = %d", offset_v);
								if (0 == bpf_xdp_adjust_head(ctx, offset_v)) {
									void *nfs_payload = (void *) (long) ctx->data;
									data_end = (void *) (long) ctx->data_end;

									__u32 *nfs_payloadl = (__u32 *) nfs_payload;
									// 拿到数据总长度
									__u32 nfs_len = __bpf_htonl(*nfs_payloadl);
									char *nfs_payloadc = (char *) (nfs_payload + sizeof(u32));

									if (nfs_payloadc + 2> (char *) data_end) {
										break;
									}
									// crc32反向校验
									crc_32 = crc32_reverse((__u8 *) nfs_payloadc, (int) nfs_len, data_end);
									bpf_map_update_elem(&XID_crc32, &XID, &crc_32, BPF_ANY);
									bpf_xdp_adjust_head(ctx, -offset_v);
								}
								bpf_xdp_adjust_head(ctx, -offset);
							}
							break;
						}
						case nfs3_ACCESS:
						case nfs3_MKDIR:
						case nfs3_CREATE:
						case nfs3_WRITE:
						case nfs3_REMOVE:
						case nfs3_RMDIR:
						case nfs3_RENAME:
						case nfs3_COMMIT:
						case nfs3_SETATTR: {
							//security config
							// check
							struct ip_ino ipIno = {
									.saddr = saddr,

							};
							access_t* access = bpf_map_lookup_elem(&security_map,&ipIno);
							if(access){
								if((*access & NFS_WRITE) == 0){
									//Security refuse
									return XDP_DROP;
								}
							}
							//attribute updated,delete cache content 
//                                bpf_printk("v3 setatrr,len = %d ,2size =%d ", data_end - (void *) rpch,
//                                           sizeof(struct nfs_rpc_headers) + sizeof(struct nfs_rpc_cred));
							if ((void *) rpch + sizeof(struct nfs_rpc_headers) + sizeof(struct nfs_rpc_cred) + 1 >
								data_end)
								break;
							struct nfs_rpc_cred
									*cred = (void *) rpch + sizeof(struct nfs_rpc_headers);
							__u32 cred_len = __bpf_htonl(cred->len);

							int offset = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) + sizeof(*rpch) + sizeof(*cred) +
											cred_len;


							if (0 == bpf_xdp_adjust_head(ctx, offset)) {
								void *newpayload = (void *) (long) ctx->data;
								void *data_end = (void *) (long) ctx->data_end;
//                                    bpf_printk("data_end - newpayload = %d", data_end - newpayload);
								struct nfs_rpc_verifier *verifier = newpayload;
								if ((void *) verifier + sizeof(struct nfs_rpc_verifier) > data_end)
									return XDP_PASS;
								__u32 ver_len = __bpf_htonl(verifier->len);
								int offset_v = sizeof(*verifier) + ver_len;
//                                    bpf_printk("offset_v = %d", offset_v);
								if (0 == bpf_xdp_adjust_head(ctx, offset_v)) {
									void *nfs_payload = (void *) (long) ctx->data;
									void *data_end = (void *) (long) ctx->data_end;

									int len = data_end - nfs_payload;
									__u32 *nfs_payloadl = (__u32 *) nfs_payload;
									//object length
									__u32 nfs_len = __bpf_htonl(*nfs_payloadl);
									//object
									char *nfs_payloadc = (char *) (nfs_payload + sizeof(u32));

									if (nfs_payloadc + 2 > (char *) data_end) {
										break;
									}
									//calculate the hash of the target file or directory
									crc_32 = crc32_reverse((__u8 *) nfs_payloadc, (int) nfs_len, data_end);


									if(p3 != nfs3_ACCESS){
										for(int i = 0;i < read_procedures_len,i++;){
											//TODO:delete all the read-related cache
											struct esnfs_cache_key cache_key = {
													.crc_32 = crc_32,
													.progVersion = nfs_v,
													.procedures3 = read_procedures[i]
											};
											struct esnfs_cache_entry *cache = bpf_map_lookup_elem(&map_kcache, &cache_key);
											//delete the cache content, waitting for the new update
											if (cache)
												bpf_map_delete_elem(&map_kcache, &cache_key);
										}
									}
									bpf_xdp_adjust_head(ctx, -offset_v);
								}
								bpf_xdp_adjust_head(ctx, -offset);
							}
							break;
						}

						default:
							break;
					}
					if(crc_32 != 0) {
						struct esnfs_cache_key cache_key = {
								.crc_32 = crc_32,
								.progVersion = prog_v,
								.procedures3 = p3
						};
						return reply_nfs(ctx, cache_key);
					}
					break;
				}
				case nfs4: 
				default: {
					break;
				}
			}
		}else {// not nfsserver
			return XDP_PASS;
		}
		break;
	default:
		return XDP_PASS;
	}
	return XDP_PASS;
}
static __always_inline int esnfs_update_cache(struct __sk_buff *skb) {
    //将非线性区的数据pull到线性区进行读取
    bpf_skb_pull_data(skb, skb->len);
    void *data_end = (void *) (long) skb->data_end;
    void *data = (void *) (long) skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    if(data +sizeof (struct ethhdr)+sizeof (struct iphdr)+sizeof (struct tcphdr)>data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;


    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);




    void *tcp_payload = tcp + sizeof(struct tcphdr);
    /******************对不带payload的包进行代理**************/
    if(__bpf_htons(ip->tot_len) == sizeof (struct iphdr)+sizeof(struct tcphdr))
    {
        /******************检查是否需要代理连接***************/
        //store&save seq,ack info
        //因为是response包所以反过来
        struct tcp_idx tcpIdx = {
                .saddr = ip->daddr,
                .daddr = ip->saddr,
                .source = tcp->dest,
                .dest = tcp->source
        };

        struct tcp_seqack *sendSeqAck = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
        if(sendSeqAck){
            __be32 temp_seq = tcp->seq;

            struct tcp_seqack recvSeqAck = {
                    .seq = tcp->ack_seq,
                    .ack = temp_seq,
            };
            __u32 dest =tcp->dest;
//            bpf_printk("send irritate ,dest = %u,seq = %u, ack = %u",__bpf_htons(dest), __bpf_htonl(recvSeqAck.seq), __bpf_htonl(recvSeqAck.ack));

//            if(0 != bpf_map_update_elem(&recv_tx_seqack_num,&tcpIdx,&recvSeqAck,BPF_ANY)){
//                return TC_ACT_OK;
//            }
            /******************修改tcp信息***************/
            tcp->seq = sendSeqAck->seq;
            tcp->ack_seq = sendSeqAck->ack;
//            __u64 checksum = 0;
//            tcp->check = 0;
//            ipv4_l4_csum((void *) tcp, &checksum, ip, data_end);
//            tcp->check = __bpf_htons(checksum);

            /******************修改tcp信息***************/
        }
        return TC_ACT_OK;
    }


    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) +
        sizeof(struct nfs_rpc_reply_headers) > data_end)
        return TC_ACT_OK;

    unsigned int zero = 0;
    //update the tcp window now
    __be16 tcp_window = tcp->window;
    bpf_map_update_elem(&tcp_window_now, &zero, &tcp_window, BPF_ANY);

    //process NLM
    if (tcp->source != __bpf_htons(nfs_port)){

        struct ip_idx ipIdx = {
                .saddr = ip->daddr,
                .daddr = ip->saddr,
        };

        struct tcp_idx *tcpIdx = bpf_map_lookup_elem(&ip_tcp_map,&ipIdx);
        if(!tcpIdx)
            return TC_ACT_OK;

        __u32 *XID_send = bpf_map_lookup_elem(&send_tx_XID_ip,&ipIdx);
        if(!XID_send)
            return TC_ACT_OK;

        void *transp = data + sizeof(*eth) + sizeof(*ip);
        struct nfs_rpc_reply_headers *nfs_rep = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);


        nfs_rep->XID = *XID_send;

        __u32 recv_XID = __bpf_htonl(__bpf_htonl(nfs_rep->XID)+1);
        bpf_map_update_elem(&recv_tx_XID,tcpIdx,&recv_XID,BPF_ANY);
        bpf_map_update_elem(&recv_tx_XID_ip,&ipIdx,&recv_XID,BPF_ANY);

        return TC_ACT_OK;
    }
    void *transp = data + sizeof(*eth) + sizeof(*ip);
    struct nfs_rpc_reply_headers *nfs_rep = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    /******************检查是否需要代理连接***************/
    //store&save seq,ack info
    //因为是response包所以反过来
    struct tcp_idx tcpIdx = {
            .saddr = ip->daddr,
            .daddr = ip->saddr,
            .source = tcp->dest,
            .dest = tcp->source
    };
    struct ip_idx ipIdx = {
            .saddr = ip->daddr,
            .daddr = ip->saddr,
    };
    struct tcp_seqack *sendSeqAck = bpf_map_lookup_elem(&send_tx_seqack_num,&tcpIdx);
    __u32 *XID_send = bpf_map_lookup_elem(&send_tx_XID,&tcpIdx);
    if(sendSeqAck && XID_send){
        /******************保存下次想要收到的数据包信息 seq,ack,XID***************/
        __be32 temp_seq = tcp->seq;
        __u32 nfs_len_origin = data_end - (void *) nfs_rep;
        __u32 seq_before = tcp->seq;
        __u32 ack_before = tcp->ack_seq;
        struct tcp_seqack recvSeqAck = {
                .seq = tcp->ack_seq,
                .ack = __bpf_htonl(__bpf_htonl(temp_seq) + nfs_len_origin),
        };
        __u32 dest =tcp->dest;
        __u32 recv_XID = __bpf_htonl(__bpf_htonl(nfs_rep->XID)+1);
// bpf_printk("send irritate need change recv ,dest = %u,seq = %u, ack = %u",__bpf_htons(dest), __bpf_htonl(recvSeqAck.seq), __bpf_htonl(recvSeqAck.ack));
// bpf_printk("irritate ,send seq_before = %u send_seq now = %u", __bpf_htonl(seq_before), __bpf_htonl(sendSeqAck->seq));
        bpf_map_update_elem(&recv_tx_XID,&tcpIdx,&recv_XID,BPF_ANY);
        bpf_map_update_elem(&recv_tx_XID_ip,&ipIdx,&recv_XID,BPF_ANY);
        if(0 != bpf_map_update_elem(&recv_tx_seqack_num,&tcpIdx,&recvSeqAck,BPF_ANY)){
            return TC_ACT_OK;
        }
        /******************修改tcp信息,add seq,ack,XID***************/
        tcp->seq = sendSeqAck->seq;
        tcp->ack_seq = sendSeqAck->ack;
        nfs_rep->XID = *XID_send;
    }
    __u8 *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    if (nfs_rep + 1 > data_end)
        return TC_ACT_OK;
    __be32 XID_temp = __bpf_htonl(nfs_rep->XID);
    enum nfs_prog_version *nfs_v = bpf_map_lookup_elem(&XID_nfsVer, &XID_temp);
    if (nfs_v == 0)
        return TC_ACT_OK;
    switch (*nfs_v) {
        case nfs2: {
            break;
        }
        case nfs3: {
            enum nfsd_procedures3 *p3 = bpf_map_lookup_elem(&v3_XID_procedures, &XID_temp);

            if (p3 == 0) {
                return TC_ACT_OK;
            }

            struct audit_nfs_data *event = bpf_ringbuf_reserve(&nfs_audit_events,sizeof (struct audit_nfs_data),BPF_ANY);
            if(!event)
                break;
            //ip addr
            event->saddr = ip->saddr;
            event->daddr = ip->daddr;
            event->source = tcp->source;
            event->dest = tcp->dest;
            event->XID = XID_temp;
            event->prog_v = nfs3;
            event->procedures3 = *p3;
            bpf_ringbuf_submit(event,BPF_ANY);
            switch (*p3) {
                case nfs3_NULL: {
//                    bpf_printk("null reply,XID:%x ,len = data_end - rpc = %d", XID_temp, data_end - (void *) nfs_rep);
                    break;
                }
                case nfs3_FSSTAT:
                case nfs3_LOOKUP:
                case nfs3_READDIRPLUS:
                case nfs3_READDIR:
                case nfs3_READ:{
                    //if need fragment then do not process
                    if(ip->frag_off != 0x40)
                        break;
                }
                case nfs3_GETATTR: {

                    __u32 *crc_32 = bpf_map_lookup_elem(&XID_crc32, &XID_temp);
                    if (crc_32 == 0)
                        break;
                    struct esnfs_cache_key cache_key = {
                            .crc_32 = *crc_32,
                            .progVersion = *nfs_v,
                            .procedures3 = *p3
                    };
                    struct esnfs_cache_entry *getattr_cache = bpf_map_lookup_elem(&map_kcache, &cache_key);

                    __u32 len = data_end - (void *) nfs_rep;
//                    bpf_printk("getattr reply, XID:%x ,len = data_end - rpc = %d",XID_temp,len);
                    if (getattr_cache != 0)//cache exist, no need to udpate
                    {
                        break;
                    }
                    if (bpf_map_update_elem(&map_kcache, &cache_key, &empty_cache, BPF_NOEXIST))
                        break;

                    getattr_cache = bpf_map_lookup_elem(&map_kcache, &cache_key);

                    if (getattr_cache == 0)
                        break;

                    if (getattr_cache->valid == 1)
                        break;

                    //新增
                    getattr_cache->p3 = *p3;

                    getattr_cache->len = len;
//                    bpf_spin_lock(&getattr_cache->lock);

                    if(len>=MAX_TCP_PAYLOAD)
                        break;

                    #pragma clang loop unroll(disable)
                    for (unsigned int i = 0; i < MAX_TCP_PAYLOAD  && (void *) payload + i + 1 <= data_end; ++i) {
                        getattr_cache->data[i] = payload[i];
                    }
//                    if((void *)payload + len>data_end)
//                        break;
//memcpy fail
//                    __builtin_memcpy(getattr_cache->data,payload,len);

                    getattr_cache->valid = 1;
//                    bpf_spin_unlock(&getattr_cache->lock);
//                    bpf_printk("copy ojbk, first byte : %x", *payload);
                    break;
                }

                default:
                    break;
            }
            bpf_map_delete_elem(&v3_XID_procedures, &XID_temp);
            break;
        }
        case nfs4: {
            break;
        }
        default:
            break;
    }
    return TC_ACT_OK;
}
SEC("tc")
int tx_filter_main(struct __sk_buff *skb) {
    void *data_end = (void *) (long) skb->data_end;
    void *data = (void *) (long) skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    unsigned int zero = 0;
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;
    if (ip + 1 > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    void *transp = data + sizeof(*eth) + sizeof(*ip);
    struct udphdr *udp;
    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
    if (tcp + 1 > data_end)
        return TC_ACT_OK;
    __be16 sport = tcp->source;
    struct esnfs_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
    if (!stats)
        return XDP_PASS;
    stats->get_resp_count++;
    int ret = esnfs_update_cache(skb);
    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";