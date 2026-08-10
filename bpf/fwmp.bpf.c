#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(test_tcp_sendmsg) {
  bpf_printk("tcp_sendmsg called");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
