#if defined(__TARGET_ARCH_x86)
#endif
#define __TARGET_ARCH_x86

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>

#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>

#include <bpf/bpf_tracing.h>

const ushort AF_INET = 2;
const ushort AF_INET6 = 10;

enum event_type { CONNECT, ACCEPT, BIND, LISTEN, CLOSE };

struct event {
  __u32 pid;
  __u32 tid;

  __u8 family;
  __u8 protocol;

  __u16 local_port;
  __u16 remote_port;

  __u8 local_addr[16];
  __u8 remote_addr[16];

  __u64 timestamp_ns;
  enum event_type type;
  __u64 sock_cookie;
  __u8 state;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);   // sock_cookie
  __type(value, __u64); // cumulative bytes
} sock_bytes_sent SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, __u64);
} sock_bytes_recv SEC(".maps");

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit, struct sock *sk, struct msghdr *msg, size_t size,
             int retval) {
  if (retval <= 0)
    return 0;
  __u64 cookie = bpf_get_socket_cookie(sk);
  __u64 *val = bpf_map_lookup_elem(&sock_bytes_sent, &cookie);
  if (val) {
    __sync_fetch_and_add(val, retval);
  } else {
    __u64 initial = retval;
    bpf_map_update_elem(&sock_bytes_sent, &cookie, &initial, BPF_ANY);
  }
  return 0;
}

SEC("fexit/tcp_cleanup_rbuf")
int BPF_PROG(tcp_cleanup_rbuf_exit, struct sock *sk, int copied) {
  if (copied <= 0)
    return 0;
  __u64 cookie = bpf_get_socket_cookie(sk);
  __u64 *val = bpf_map_lookup_elem(&sock_bytes_recv, &cookie);
  if (val) {
    __sync_fetch_and_add(val, copied);
  } else {
    __u64 initial = copied;
    bpf_map_update_elem(&sock_bytes_recv, &cookie, &initial, BPF_ANY);
  }
  return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0;

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;

  event->timestamp_ns = bpf_ktime_get_ns();

  event->family = AF_INET;
  event->protocol = 6;

  __u32 local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

  __u32 remote_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

  __builtin_memcpy(event->local_addr, &local_addr, 4);
  __builtin_memcpy(event->remote_addr, &remote_addr, 4);

  event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);

  event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  event->type = CONNECT;

  event->sock_cookie = bpf_get_socket_cookie(sk);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(tcp_v6_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0;

  struct event *event;

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;

  event->timestamp_ns = bpf_ktime_get_ns();
  event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

  event->family = AF_INET6;
  event->protocol = IPPROTO_TCP;

  struct in6_addr local_addr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);

  struct in6_addr remote_addr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);

  __builtin_memcpy(event->local_addr, local_addr.in6_u.u6_addr8, 16);

  __builtin_memcpy(event->remote_addr, remote_addr.in6_u.u6_addr8, 16);

  event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  event->remote_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

  event->type = CONNECT;

  event->sock_cookie = bpf_get_socket_cookie(sk);

  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept, struct sock *sk, struct proto_accept_arg *arg,
             struct sock *retval) {
  if (!retval)
    return 0;
  struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;
  event->timestamp_ns = bpf_ktime_get_ns();
  __u16 family = BPF_CORE_READ(retval, __sk_common.skc_family);
  event->family = (__u8)family;
  event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

  event->protocol = IPPROTO_TCP;
  if (family == AF_INET) {
    __u32 local_addr = BPF_CORE_READ(retval, __sk_common.skc_rcv_saddr);
    __u32 remote_addr = BPF_CORE_READ(retval, __sk_common.skc_daddr);
    __builtin_memcpy(event->local_addr, &local_addr, sizeof(local_addr));
    __builtin_memcpy(event->remote_addr, &remote_addr, sizeof(remote_addr));
  } else if (family == AF_INET6) {
    BPF_CORE_READ_INTO(event->local_addr, retval,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(event->remote_addr, retval,
                       __sk_common.skc_v6_daddr.in6_u.u6_addr8);
  } else {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }
  event->local_port = BPF_CORE_READ(retval, __sk_common.skc_num);
  event->remote_port = bpf_ntohs(BPF_CORE_READ(retval, __sk_common.skc_dport));
  event->type = ACCEPT;
  event->sock_cookie = bpf_get_socket_cookie(retval);
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int retval) {
  if (retval != 0 || !sock || !sock->sk)
    return 0;

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event->state = BPF_CORE_READ(sock, sk, __sk_common.skc_state);
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;
  event->timestamp_ns = bpf_ktime_get_ns();

  __u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);

  event->family = (__u8)family;
  event->protocol = IPPROTO_TCP;

  if (family == AF_INET) {
    struct sockaddr_in addr = {};

    if (bpf_probe_read_kernel(&addr, sizeof(addr), uaddr) == 0) {
      event->local_port = bpf_ntohs(addr.sin_port);
      __builtin_memcpy(event->local_addr, &addr.sin_addr,
                       sizeof(addr.sin_addr));
    }
  } else if (family == AF_INET6) {
    struct sockaddr_in6 addr = {};

    if (bpf_probe_read_kernel(&addr, sizeof(addr), uaddr) == 0) {
      event->local_port = bpf_ntohs(addr.sin6_port);
      __builtin_memcpy(event->local_addr, &addr.sin6_addr,
                       sizeof(addr.sin6_addr));
    }
  } else {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }

  event->type = BIND;
  event->sock_cookie = bpf_get_socket_cookie(sock->sk);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("fexit/inet_listen")
int BPF_PROG(inet_listen, struct socket *sock, int backlog, int retval) {
  if (retval != 0 || !sock || !sock->sk)
    return 0;

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();

  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;
  event->timestamp_ns = bpf_ktime_get_ns();

  __u16 family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
  event->state = BPF_CORE_READ(sock, sk, __sk_common.skc_state);

  event->family = (__u8)family;
  event->protocol = IPPROTO_TCP;

  if (family == AF_INET) {
    __be32 addr = BPF_CORE_READ(sock, sk, __sk_common.skc_rcv_saddr);
    __u16 port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);

    event->local_port = port;
    __builtin_memcpy(event->local_addr, &addr, sizeof(addr));
  } else if (family == AF_INET6) {
    struct in6_addr addr =
        BPF_CORE_READ(sock, sk, __sk_common.skc_v6_rcv_saddr);
    __u16 port = BPF_CORE_READ(sock, sk, __sk_common.skc_num);

    event->local_port = port;
    __builtin_memcpy(event->local_addr, &addr, sizeof(addr));
  } else {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }

  event->type = LISTEN;
  event->sock_cookie = bpf_get_socket_cookie(sock->sk);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

SEC("fexit/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk, long int timeout) {
  if (!sk)
    return 0;

  struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->pid = pid_tgid >> 32;
  event->tid = (__u32)pid_tgid;

  event->timestamp_ns = bpf_ktime_get_ns();

  event->family = AF_INET;
  event->protocol = 6;
  event->state = BPF_CORE_READ(sk, __sk_common.skc_state);

  __u32 local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);

  __u32 remote_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

  __builtin_memcpy(event->local_addr, &local_addr, 4);
  __builtin_memcpy(event->remote_addr, &remote_addr, 4);

  event->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);

  event->remote_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  event->type = CLOSE;

  event->sock_cookie = bpf_get_socket_cookie(sk);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
