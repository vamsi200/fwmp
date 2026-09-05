module fetch;
import std::io;
import libbpf;
import linsys;
import std::collections::list;
import std::collections::map;
import std::thread::channel;
import std::time;
import std::net::os;
import libc;
import libpcap;

const ushort AF_INET  = 2;
const ushort AF_INET6 = 10;

struct Application {
    String name;
    String executable;
}

fn uint Application.hash(Application self) {
    return self.executable.hash();
}

fn bool Application.equals(Application self, Application other) {
    return self.executable == other.executable;
}

enum EventType {
    CONNECT,
    ACCEPT,
    BIND,
    LISTEN,
    CLOSE,
    STATE_CHANGE,
}

struct Event {
    uint pid;
    uint tid;

    char family;
    char protocol;

    ushort local_port;
    ushort remote_port;

    char[16] local_addr;
    char[16] remote_addr;

    ulong timestamp_ns;
    EventType event_type;
    ulong sock_cookie;
    char state;
}

alias SocketId = ulong;
alias AppId = ulong;

struct Socket {
    SocketIdentity identity;

    SocketState state;

    SocketId sock_cookie;

    ulong app_id;
    uint pid;
    Clock last_seen;
}


enum SocketState {
    ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT1,
    FIN_WAIT2,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    LAST_ACK,
    LISTEN,
    CLOSING,
    UNKNOWN
}

struct SocketIdentity {
    Endpoint local;
    Endpoint remote;
    Protocol protocol;
    char family;
}

struct Endpoint {
    char[16] addr;
    ushort port;
}

struct NetworkStats {
    BpfMap* sent;
    BpfMap* recv;
}

fn TrafficStats NetworkStats.traffic(NetworkStats* self, ulong cookie) {
    ulong sent = lookup_bytes(self.sent, cookie);
    ulong recv = lookup_bytes(self.recv, cookie);

    return { .sock_cookie = cookie, .sent = sent, .received = recv };
}

struct TrafficStats {
    ulong sock_cookie;
    ulong sent;
    ulong received;
}

enum Protocol {
    TCP,
    UDP
}

fn String convert_ip(Allocator allocator, ushort family, char[16] addr) {
    switch (family) {
        case AF_INET:
            return string::format(
                allocator,
                "%d.%d.%d.%d",
                (uint)addr[0] & 0xFF,
                (uint)addr[1] & 0xFF,
                (uint)addr[2] & 0xFF,
                (uint)addr[3] & 0xFF
            );

        case AF_INET6:
            return string::format(
                allocator,
                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                addr[0],
                addr[1],
                addr[2],
                addr[3],
                addr[4],
                addr[5],
                addr[6],
                addr[7],
                addr[8],
                addr[9],
                addr[10],
                addr[11],
                addr[12],
                addr[13],
                addr[14],
                addr[15]
            );

        default:
            return string::format(allocator, "<unknown>");
    }
}


struct RingBufContext {
    List{Event} events;
    bool has_value;
}

fn int ringbuf_callback(void* ctx, void* data, usz size) {
    RingBufContext* context = ctx;
    if (size != Event::size) return 0;

    Event event;
    mem::copy(&event, data, Event::size);
    context.events.push(event);
    context.has_value = true;
    return 0;
}

struct HostnameEvent {
    char[4] ip;
    String hostname;
}

struct NetworkChannel {
    LibcAllocator libc;
    BufferedChannel{Event}* channel;
    BufferedChannel{NetworkSnapshot}* snapshot_channel;
    BufferedChannel{HostnameEvent}* hostname_channel;
    int map_fd;
    RingBufContext* ring_buf_ctx;
    RingBuffer* rb;
    NetworkStats network_stats;
    NanoDuration fetch_interval;
    HashMap{Application, ulong} app_map;
    HashMap{ulong, Socket} sock_map;
    HashMap{uint, ProcessInfo} process_map;
    HashMap{char[4], String} sni_cache;
    ulong next_app_id;
    NanoDuration retention;
    bool quit;
}

fn ulong lookup_bytes(BpfMap* map, ulong cookie) {
    ulong value = 0;
    int ret     = libbpf::bpf_map__lookup_elem(map, &cookie, ulong::size, &value, ulong::size, 0);
    if (ret != 0) {
        return 0;
    }
    return value;
}

fn void fetch_data_from_ebpf(NetworkChannel* nc) {
    LibcAllocator libc;

    @pool_init(&libc, 8192) {
        List{ulong} live_cookies;
        live_cookies.init(tmem);

        while (true && !nc.quit) {
            int ret = libbpf::ring_buffer__poll(nc.rb, 100);

            if (ret < 0) {
                io::printfn("poll error: %d", ret);
                break;
            }

            foreach (event : nc.ring_buf_ctx.events) {
                if (event.event_type == EventType.CLOSE) {
                    foreach (i, cookie : live_cookies) {
                        if (cookie == event.sock_cookie) {
                            live_cookies.remove_at(i);
                            break;
                        }
                    }
                } else {
                    bool tracked = false;

                    foreach (cookie : live_cookies) {
                        if (cookie == event.sock_cookie) {
                            tracked = true;
                            break;
                        }
                    }

                    if (!tracked) {
                        live_cookies.push(event.sock_cookie);
                    }
                }

                if (!@ok(nc.channel.try_push(event))) {
                    io::printn("Failed to send event");
                }
            }

            nc.ring_buf_ctx.events.clear();
        }
    };
}

faultdef EVENT_NOT_FOUND_ERROR, EXISTING_SOCKET, NO_PTR_RECORD_ERROR, NAMEINFO_FAILED, NOT_TLS_ERROR, NOT_CLIENT_HELLO_ERROR, MALFORMED_ERROR, NO_SNI_FOUND_ERROR;


struct NetworkInfo {
    Event event;
    ProcessInfo process_info;
}

fn SocketState get_state(char state) {
    switch (state) {
        case 1:
            return ESTABLISHED;
        case 2:
            return SYN_SENT;
        case 3:
            return SYN_RECV;
        case 4:
            return FIN_WAIT1;
        case 5:
            return FIN_WAIT2;
        case 6:
            return TIME_WAIT;
        case 7:
            return CLOSE;
        case 8:
            return CLOSE_WAIT;
        case 9:
            return LAST_ACK;
        case 10:
            return LISTEN;
        case 11:
            return CLOSING;
        default:
            return UNKNOWN;
    }
}

fn NetworkInfo? get_process_info(NetworkChannel* recv) {
    @pool_init(&recv.libc, 8192) {
        NetworkInfo ni = { };
        Event? ev      = recv.channel.try_pop();
        if (catch ev) return EVENT_NOT_FOUND_ERROR~;

        if (ev.event_type == EventType.STATE_CHANGE) {
            Socket? existing = recv.sock_map.get(ev.sock_cookie);
            if (catch existing) return EVENT_NOT_FOUND_ERROR~;

            existing.state = get_state(ev.state);
            existing.last_seen = clock::now();
            recv.sock_map.set(ev.sock_cookie, existing);

            ni.event = ev;
            return ni;
        }

        ProcessInfo? cached = recv.process_map.get((uint)ev.pid);
        ProcessInfo pi;

        if (catch cached) {
            pi = linsys::process::info(&recv.libc, (int)ev.pid) ?? { };

            ProcessInfo process_copy = {
                .process = {
                    .pid = pi.process.pid,
                    .ppid = pi.process.ppid,
                    .name = pi.process.name.copy(&recv.libc),
                    .state = pi.process.state,
                },
                .exe_path = pi.exe_path.copy(&recv.libc),
                .cmdline = pi.cmdline.copy(&recv.libc),
                .uid = pi.uid,
                .gid = pi.gid,
                .threads = pi.threads,
                .vm_size = pi.vm_size,
                .vm_rss = pi.vm_rss,
            };

            recv.process_map.set((uint)ev.pid, process_copy);
        } else {
            pi = cached;
        }

        Application app = {
            .name = pi.process.name.copy(&recv.libc),
            .executable = pi.exe_path.copy(&recv.libc),
        };

        ulong app_id;
        if (recv.app_map.has_key(app)) {
            app_id = recv.app_map.get(app)!!;
            app.name.free(&recv.libc);
            app.executable.free(&recv.libc);
        } else if (app.executable.len > 0) {
            recv.next_app_id += 1;
            app_id = recv.next_app_id;
            recv.app_map.set(app, app_id);
        } else {
            app.name.free(&recv.libc);
            app.executable.free(&recv.libc);
        }

        Endpoint local = { .addr = ev.local_addr, .port = ev.local_port };

        Endpoint remote = { .addr = ev.remote_addr, .port = ev.remote_port };

        SocketIdentity identity = {
            .local = local,
            .remote = remote,
            .protocol = Protocol.TCP,
            .family = ev.family
        };

        Socket new_socket = {
            .identity = identity,
            .state = get_state(ev.state),
            .sock_cookie = ev.sock_cookie,
            .app_id = app_id,
            .pid = (uint)ev.pid,
            .last_seen = clock::now(),
        };

        recv.sock_map.set(ev.sock_cookie, new_socket);

        ni.event = ev;
        ni.process_info = pi;
        return ni;
    };
}

typedef SockAddrPtr = void*;
const NI_MAXHOST = 1000;

extern fn CInt getnameinfo(
    SockAddrPtr sa,
    Socklen_t salen,
    ZString host,
    Socklen_t hostlen,
    ZString serv,
    Socklen_t servlen,
    CInt flags
) @cname("getnameinfo");

fn SockAddrPtr build_sockaddr(char[] addr_bytes, ushort family) @if(os::SUPPORTS_INET) => @pool() {
    if (family == AF_INET) {
        SockAddrIn* sa = mem::tnew(SockAddrIn);
        *sa = { .sin_family = AF_INET, .sin_port = 0, .sin_addr = 0, .sin_zero = { } };

        mem::copy(&sa.sin_addr, addr_bytes.ptr, 4);
        return (SockAddrPtr)sa;
    }

    SockAddrIn6* sa6 = mem::tnew(SockAddrIn6);
    *sa6 = {
        .sin6_family = AF_INET6,
        .sin6_port = 0,
        .sin6_flowinfo = 0,
        .sin6_addr = { },
        .sin6_scope_id = 0
    };

    mem::copy(&sa6.sin6_addr, addr_bytes.ptr, 16);
    return (SockAddrPtr)sa6;
}

fn Socklen_t sockaddr_len(ushort family) {
    return family == AF_INET ? SockAddrIn::size : SockAddrIn6::size;
}

const NI_NAMEREQD = 0x0008;

fn String? nameinfo(char[] addr_bytes, ushort family, LibcAllocator alloc) @if(os::SUPPORTS_INET) {
    @pool_init(&alloc, 256) {
        char[NI_MAXHOST] host_buf;
        SockAddrPtr sa = build_sockaddr(addr_bytes, family);
        if (getnameinfo(
            sa,
            sockaddr_len(family),
            (ZString)&host_buf,
            NI_MAXHOST,
            null,
            0,
            NI_NAMEREQD
        )) {
            return NAMEINFO_FAILED~;
        }
        return ((ZString)&host_buf).copy(&alloc);
    };
}

fn void? collect_network_snapshot(NetworkChannel* network_channel, List{ulong}* to_remove) {
    Clock start = clock::now();

    List{Socket} sockets_list;
    sockets_list.init(&network_channel.libc);

    List{TrafficStats} traffic_stats_list;
    traffic_stats_list.init(&network_channel.libc);

    List{InspectInformation} inspect_info_list;
    inspect_info_list.init(&network_channel.libc);

    to_remove.clear();

    for (;;) {
        HostnameEvent? he = network_channel.hostname_channel.try_pop();
        if (catch he) break;
        network_channel.sni_cache.set(he.ip, he.hostname);
    }

    for (;;) {
        if (clock::now() - start >= network_channel.fetch_interval) {
            break;
        }

        NetworkInfo? info = get_process_info(network_channel);
        if (catch info) {
            continue;
        }
    }

    foreach (sock : network_channel.sock_map.value_iter()) {
        ulong sent = lookup_bytes(network_channel.network_stats.sent, sock.sock_cookie);

        ulong recv = lookup_bytes(network_channel.network_stats.recv, sock.sock_cookie);

        TrafficStats traffic_stats = {
            .sock_cookie = sock.sock_cookie,
            .sent = sent,
            .received = recv
        };

        ProcessInfo? process_info = network_channel.process_map.get(sock.pid);
        if (catch process_info) {
            continue;
        }

        String? host_lookup = network_channel.sni_cache.get(sock.identity.remote.addr[..3]);
        String hostname     = host_lookup ?? "";

        InspectInformation inspect_info = {
            .remote_addr = sock.identity.remote.addr,
            .local_addr = sock.identity.local.addr,
            .local_port = sock.identity.local.port,
            .remote_port = sock.identity.remote.port,
            .pid = (int)sock.pid,
            .sock_state = sock.state,
            .traffic_stats = traffic_stats,
            .ppid = process_info.process.ppid,
            .process_name = process_info.process.name,
            .hostname = hostname,
            .state = process_info.process.state,
            .exe_path = process_info.exe_path,
            .cmdline = process_info.cmdline,
            .uid = process_info.uid,
            .family = sock.identity.family,
            .protocol = sock.identity.protocol,
            .sock_cookie = sock.sock_cookie
            };

        sockets_list.push(sock);
        traffic_stats_list.push(traffic_stats);


        inspect_info_list.push(inspect_info);
    }

    foreach (sock : network_channel.sock_map.value_iter()) {
        if (sock.state == SocketState.CLOSE
            && clock::now() - sock.last_seen >= network_channel.retention) {
            to_remove.push(sock.sock_cookie);
        }
    }

    foreach (cookie : to_remove) {
        network_channel.sock_map.remove(cookie);
    }

    NetworkSnapshot ns = {
        .app = network_channel.app_map,
        .sock = sockets_list,
        .traffic_stats = traffic_stats_list,
        .information = inspect_info_list,
    };

    if (!@ok(network_channel.snapshot_channel.try_push(ns))) {
        io::printn("failed to send snapshot");
    }

    return;
}

struct InspectInformation {
    // Process Information
    int pid;
    int ppid;
    String process_name;
    ProcState state;
    String exe_path;
    String cmdline;
    int uid;

    // Event
    char[16] remote_addr;
    char[16] local_addr;
    ushort local_port;
    ushort remote_port;
    char family;
    Protocol protocol;
    String hostname;
    // String cname;
    // String Cert;
    // String resolver;
    SocketState sock_state;
    TrafficStats traffic_stats;
    ulong sock_cookie;
}

struct NetworkSnapshot {
    HashMap{Application, ulong} app;
    List{Socket} sock;
    List{TrafficStats} traffic_stats;
    List{InspectInformation} information;
}

fn void? snapshot_loop(NetworkChannel* network_channel) {
    List{ulong} to_remove;
    to_remove.init(&network_channel.libc);
    defer to_remove.free();

    while (true && !network_channel.quit) {
        if (catch collect_network_snapshot(network_channel, &to_remove)) return;
    }
}

fn ushort bswap16(ushort v) {
    return (ushort)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF));
}

// TLS record header (5 bytes)
//   content_type   = 0x16 (handshake)
//   version        (2 bytes, ignore)
//   length         (2 bytes)
// Handshake header (4 bytes)
//   msg_type       = 0x01 (ClientHello)
//   length         (3 bytes)
// ClientHello body
//   version (2) + random (32) + session_id_len (1) + session_id (var)
//   + cipher_suites_len (2) + cipher_suites (var)
//   + compression_methods_len (1) + compression_methods (var)
//   + extensions_len (2)
//   extensions[]:
//     ext_type (2) + ext_len (2) + ext_data (var)
//     if ext_type == 0x0000 (server_name)
//       inside: server_name_list_len (2) + entry_type (1, 0x00=hostname)
//               + hostname_len (2) + hostname bytes

fn String? extract_sni(Allocator alloc, char[] tcp_payload) {
    if (tcp_payload.len < 9) return NOT_TLS_ERROR~;
    if (tcp_payload[0] != 0x16) return NOT_TLS_ERROR~; // not a handshake record
    if (tcp_payload[5] != 0x01) return NOT_CLIENT_HELLO_ERROR~; // not ClientHello

    uint pos = 5 + 4; // skip record header (5) + handshake header (4)
    if ((long)pos + 34 > tcp_payload.len) return MALFORMED_ERROR~;
    pos += 2 + 32; // client_version(2) + random(32)

    char session_id_len = tcp_payload[pos];
    pos += 1 + (uint)session_id_len;
    if ((long)pos + 2 > tcp_payload.len) return MALFORMED_ERROR~;

    ushort cipher_suites_len = bswap16(*(ushort*)&tcp_payload[pos]);
    pos += 2 + (uint)cipher_suites_len;
    if ((long)pos + 1 > tcp_payload.len) return MALFORMED_ERROR~;

    char compression_len = tcp_payload[pos];
    pos += 1 + (uint)compression_len;
    if ((long)pos + 2 > tcp_payload.len) return MALFORMED_ERROR~;

    ushort ext_total_len = bswap16(*(ushort*)&tcp_payload[pos]);
    pos += 2;
    uint ext_end = pos + (uint)ext_total_len;
    if (ext_end > tcp_payload.len) return MALFORMED_ERROR~;

    while (pos + 4 <= ext_end) {
        ushort ext_type = bswap16(*(ushort*)&tcp_payload[pos]);
        ushort ext_len  = bswap16(*(ushort*)&tcp_payload[pos + 2]);
        pos += 4;
        if (pos + ext_len > ext_end) return MALFORMED_ERROR~;

        if (ext_type == 0x0000) {
            uint sni_pos = pos + 2 + 1; // skip list_len(2) + entry_type(1)
            if (sni_pos + 2 > pos + ext_len) return MALFORMED_ERROR~;
            ushort host_len = ((ushort)tcp_payload[sni_pos] << 8)
                | (ushort)tcp_payload[sni_pos + 1];
            sni_pos += 2;
            if (sni_pos + host_len > pos + ext_len) return MALFORMED_ERROR~;

            String sni_view = (String)tcp_payload[sni_pos..sni_pos + host_len - 1];
            return sni_view;
        }
        pos += ext_len;
    }

    return NO_SNI_FOUND_ERROR~;
}

struct HostnameArgs {
    Pcap_t* pcap;
    LibcAllocator libc;
    BufferedChannel{HostnameEvent}* hostname_channel;
    bool* quit;
}

fn void fetch_hostname(HostnameArgs* hostname_args) {
    Pcap_t* pcap = hostname_args.pcap;
    while (!*hostname_args.quit) {
        char* data;
        Pcap_pkthdr* header;
        CInt out = pcap::pcap_next_ex(pcap, &header, &data);
        if (out == 0) continue;
        if (out == -1) {
            io::printfn("capture error: %s", pcap::pcap_geterr(pcap));
            continue;
        }

        char[] frame = data[:(usz)header.caplen];
        if (frame.len < 14) continue;
        char[] ip_pkt = frame[14..];
        if (ip_pkt.len < 20) continue;

        // high nibble is ip version and lower is internet header length
        char ihl        = ip_pkt[0] & 0x0F;
        uint ip_hdr_len = (uint)ihl * 4;
        if (ip_pkt.len < ip_hdr_len) continue;
        char protocol = ip_pkt[9];

        char[] l4_payload = ip_pkt[ip_hdr_len..];

        if (protocol == 6) {
            char data_offset = (l4_payload[12] >> 4) & 0x0F;
            uint tcp_hdr_len = (uint)data_offset * 4;
            if (l4_payload.len < tcp_hdr_len) continue;
            char[] tcp_payload = l4_payload[tcp_hdr_len..];

            String? sni = extract_sni(tmem, tcp_payload);
            if (catch sni) continue;

            char[4] dst_ip;
            mem::copy(&dst_ip, &ip_pkt[16], 4);
            HostnameEvent he = { .ip = dst_ip, .hostname = sni.copy(&hostname_args.libc) };
            if (!@ok(hostname_args.hostname_channel.try_push(he))) {
                io::printn("failed to send hostname event");
            }
        }
    }
}
