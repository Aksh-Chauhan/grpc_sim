#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define HLF_GOSSIP_PORT_1 50051
#define HLF_GOSSIP_PORT_2 50052
#define HLF_GOSSIP_PORT_3 50053

struct gossip_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
    __u32 ack;
    __u32 msg_type;
    __u32 payload_len;
    char payload[400];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} gossip_events SEC(".maps");

static __always_inline int parse_ethernet_header(void *data, void *data_end, struct ethhdr **eth) {
    *eth = data;
    if ((void *)(*eth + 1) > data_end) return -1;
    if ((*eth)->h_proto != bpf_htons(ETH_P_IP)) return -1;
    return 0;
}

static __always_inline int parse_ip_header(void *data, void *data_end, struct iphdr **ip) {
    *ip = data;
    if ((void *)(*ip + 1) > data_end) return -1;
    if ((*ip)->protocol != IPPROTO_TCP) return -1;
    return 0;
}

static __always_inline int parse_tcp_header(void *data, void *data_end, struct tcphdr **tcp) {
    *tcp = data;
    if ((void *)(*tcp + 1) > data_end) return -1;
    return 0;
}

SEC("xdp")
int capture_hlf_gossip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth;
    if (parse_ethernet_header(data, data_end, &eth) < 0) return XDP_PASS;

    struct iphdr *ip;
    if (parse_ip_header((void *)(eth + 1), data_end, &ip) < 0) return XDP_PASS;

    struct tcphdr *tcp;
    if (parse_tcp_header((void *)ip + (ip->ihl << 2), data_end, &tcp) < 0) return XDP_PASS;

    // Check for HLF gossip TCP port
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);
    if (src_port != HLF_GOSSIP_PORT_1 && dst_port != HLF_GOSSIP_PORT_1 && src_port != HLF_GOSSIP_PORT_2 && dst_port != HLF_GOSSIP_PORT_2 && src_port != HLF_GOSSIP_PORT_3 && dst_port != HLF_GOSSIP_PORT_3) return XDP_PASS;

    // Calculate IP Header Length
    __u16 ip_header_length = ip->ihl * 4; // in bytes

    // Calculate TCP Header Length
    __u16 tcp_header_length = tcp->doff * 4; // in bytes

    // Get Total Length of IP Packet
    __u16 total_length = bpf_ntohs(ip->tot_len); // Total length from IP header

    // Calculate TCP Payload Length
    __u32 tcp_payload_length = total_length - ip_header_length - tcp_header_length;

    // Ensure the payload length is valid
    if (tcp_payload_length <= 0) return XDP_PASS; // Check if payload length is valid

    // Get TCP Payload
    char *payload = (char *)tcp + tcp_header_length; // Correctly calculate the payload start
    char *payload_end = (char *)data_end;

    // Ensure the payload does not exceed the data bounds
    if (payload + tcp_payload_length > payload_end) {
        return XDP_PASS; // Prevent out-of-bounds access
    }

    unsigned char http2_frame_type_byte;
    if (bpf_probe_read_kernel(&http2_frame_type_byte, sizeof(http2_frame_type_byte), payload + 3)!=0){
        return XDP_PASS;
    }

    // Extract gossip message
    struct gossip_event event = {0};
    event.src_ip = ip->saddr;
    event.dst_ip = ip->daddr;
    event.src_port = src_port;
    event.dst_port = dst_port;
    event.seq = bpf_ntohl(tcp->seq);
    event.ack = bpf_ntohl(tcp->ack_seq);
    event.msg_type = http2_frame_type_byte;
    event.payload_len = tcp_payload_length; // Set the calculated payload length

    // Copy the payload to the event structure
    int copy_len = event.payload_len < sizeof(event.payload) ? event.payload_len : sizeof(event.payload) - 1;
    bpf_probe_read_kernel(&event.payload, copy_len, payload);
    event.payload[copy_len] = '\0'; // Null-terminate the payload string

    // Submit to userspace
    bpf_perf_event_output(ctx, &gossip_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
