//go:build ignore

#include <linux/types.h>
#include <arpa/inet.h>
#include "libbpf/src/bpf_endian.h"
#include "libbpf/src/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <string.h>
#include <linux/udp.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define ETH_PRO_IP 0x0008

// ================= //
// == TLS Structs == //
// ================= //

typedef struct packet {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;

    __u32 x_request_id;
} packet;

const struct packet *unused1 __attribute__((unused));

// ============== //
// == BPF Maps == //
// ============== //
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u16));
  __uint(max_entries, 4096);
} pod_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096 * 2);
} packet_result_map SEC(".maps");


// =================== //
// == BPF Functions == //
// =================== //


// ================== //
// == BPF Programs == //
// ================== //
SEC("tc")
int packet_analyzer_agent(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (ctx->len != data_end - data) {
    bpf_skb_pull_data(ctx, ctx->len);
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
  }
  if (data_end - data < ctx->len) {
    return TC_ACT_OK;
  }

  struct ethhdr *ethptr = data;
  if ((void *)&ethptr[1] > data_end) {
    return TC_ACT_OK;
  }

  if (ethptr->h_proto == ETH_PRO_IP) {
    struct iphdr *ipptr = (void *)ethptr + sizeof(struct ethhdr);
    if ((void *)&ipptr[1] > data_end) {
      return TC_ACT_OK;
    }

    if (ipptr->protocol == IPPROTO_TCP) {
      struct tcphdr *tcpptr = ((void *)ipptr) + (ipptr->ihl << 2);
      if ((void *)&tcpptr[1] > data_end) {
        return TC_ACT_OK;
      }

      struct packet *packet_info = bpf_ringbuf_reserve(&packet_result_map, sizeof(*packet_info), 0);
      if (!packet_info) {
        return TC_ACT_OK;
      }


      packet_info->src_ip = ipptr->saddr;
      packet_info->dst_ip = ipptr->daddr;
      packet_info->src_port = tcpptr->source;
      packet_info->dst_port = tcpptr->dest;
      // packet_info->x_request_id = x_request_id; 
      bpf_ringbuf_submit(packet_info, 0);
    }

  
    return TC_ACT_OK;
  }

  return TC_ACT_OK;
}