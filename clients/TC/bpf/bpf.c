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

#define MAX_ITERATIONS 64       // Maximum iterations for searching the header
#define X_REQUEST_ID_MAX_LEN 36 // Maximum length of X-Request-ID value

typedef struct packet {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u16 identification;
    __u32 tcp_seq;
    char x_request_id[X_REQUEST_ID_MAX_LEN]; // Changed to a character array
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

// ================== //
// == BPF Programs == //
// ================== //
SEC("tc")
int packet_analyzer_agent(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure data pointers are valid
    if (data >= data_end) {
        return TC_ACT_OK;
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // Check if it's IP
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // Parse IP header
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            return TC_ACT_OK;
        }

        // Check if it's TCP
        if (ip->protocol == IPPROTO_TCP) {
            // Parse TCP header
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) > data_end) {
                return TC_ACT_OK;
            }

            // Calculate payload pointer
            char *payload = (void *)tcp + (tcp->doff * 4);
            if (payload >= (char *)data_end) {
                return TC_ACT_OK;
            }

            // Calculate the maximum number of bytes we can safely read
            int max_bytes = (char *)data_end - payload;
            if (max_bytes <= 0) {
                return TC_ACT_OK;
            }

            // Limit the maximum number of bytes to search
            if (max_bytes > MAX_ITERATIONS + 12) { // +12 for the length of "x-request-id"
                max_bytes = MAX_ITERATIONS + 12;
            }

            // Reserve space for packet_info
            struct packet *packet_info = bpf_ringbuf_reserve(&packet_result_map, sizeof(*packet_info), 0);
            if (!packet_info) {
                return TC_ACT_OK;
            }

            // Initialize x_request_id
            #pragma unroll
            for (int idx = 0; idx < X_REQUEST_ID_MAX_LEN; idx++) {
                packet_info->x_request_id[idx] = 0;
            }

            // Search for "x-request-id" in the payload
            int found = 0;

            // Use a fixed loop with a known number of iterations
            #pragma unroll
            for (int i = 0; i < MAX_ITERATIONS; i++) {
                // Ensure we don't read beyond data_end
                if (payload + i + 12 > (char *)data_end) {
                    break;
                }

                // Compare "x-request-id" character by character
                char *p = payload + i;

                if (p[0] == 'x' && p[1] == '-' && p[2] == 'r' && p[3] == 'e' &&
                    p[4] == 'q' && p[5] == 'u' && p[6] == 'e' && p[7] == 's' &&
                    p[8] == 't' && p[9] == '-' && p[10] == 'i' && p[11] == 'd') {

                    found = 1;
                    // Move pointer to the value after "x-request-id"
                    char *value_ptr = p + 12;

                    // Skip colon and whitespace
                    #pragma unroll
                    for (int j = 0; j < 4; j++) {
                        if (value_ptr >= (char *)data_end) {
                            break;
                        }
                        char c = *value_ptr;
                        if (c == ':') {
                            value_ptr++;
                            break;
                        } else if (c == ' ' || c == '\t') {
                            value_ptr++;
                        } else {
                            break;
                        }
                    }

                    // Skip any additional whitespace
                    #pragma unroll
                    for (int j = 0; j < 4; j++) {
                        if (value_ptr >= (char *)data_end) {
                            break;
                        }
                        char c = *value_ptr;
                        if (c == ' ' || c == '\t') {
                            value_ptr++;
                        } else {
                            break;
                        }
                    }

                    // Extract the value as a string
                    int id_len = 0;
                    #pragma unroll
                    for (int k = 0; k < X_REQUEST_ID_MAX_LEN - 1; k++) {
                        if (value_ptr + k >= (char *)data_end) {
                            break;
                        }
                        char c = value_ptr[k];
                        if (c == '\r' || c == '\n') {
                            break;
                        }
                        packet_info->x_request_id[k] = c;
                        id_len++;
                    }
                    packet_info->x_request_id[id_len] = '\0'; // Null-terminate the string
                    break;
                }
            }

            // Fill other packet_info fields
            packet_info->src_ip = ip->saddr;
            packet_info->dst_ip = ip->daddr;
            packet_info->src_port = tcp->source;
            packet_info->dst_port = tcp->dest;
            packet_info->tcp_seq = bpf_ntohl(tcp->seq);
            packet_info->identification = ip->id;

            bpf_ringbuf_submit(packet_info, 0);
        }
    }
    return TC_ACT_OK;
}
