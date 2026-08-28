module fetch;
import std::io;
import libbpf;
import linsys;
import std::collections::list;
import std::collections::map;
import std::thread::channel;
import std::time;

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

struct NetworkChannel {
    LibcAllocator libc;
    BufferedChannel{Event}* channel;
    BufferedChannel{NetworkSnapshot}* snapshot_channel;
    int map_fd;
    RingBufContext* ring_buf_ctx;
    RingBuffer* rb;
    NetworkStats network_stats;
    NanoDuration duration;
    HashMap{Application, ulong} app_map;
    HashMap{ulong, Socket} sock_map;
    ulong next_app_id;
    NanoDuration retention;
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

        while (true) {
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

faultdef EVENT_NOT_FOUND_ERROR, EXISTING_SOCKET;

struct NetworkInfo {
    Event event;
    ProcessInfo process_info;
}

fn NetworkInfo? get_process_info(NetworkChannel* recv) {
    @pool_init(&recv.libc, 8192) {
        NetworkInfo ni = { };
        Event? ev = recv.channel.try_pop();
        if (catch ev) return EVENT_NOT_FOUND_ERROR~;

        if (ev.event_type == EventType.CLOSE) {
            Socket? existing = recv.sock_map.get(ev.sock_cookie);
            if (catch existing) return EVENT_NOT_FOUND_ERROR~;
            existing.state = SocketState.CLOSE;
            existing.last_seen = clock::now();
        }

        ProcessInfo pi  = linsys::process::info(&recv.libc, (int)ev.pid) ?? { };
        Application app = {
            .name = pi.process.name,
            .executable = pi.exe_path,
        };

        ulong app_id;
        if (recv.app_map.has_key(app)) {
            app_id = recv.app_map.get(app)!!;
        } else {
            if (app.executable.len > 0) {
                io::printfn("inserted: %s = %s", app.name, app.executable);
                recv.next_app_id += 1;
                app_id = recv.next_app_id;
                recv.app_map.set(app, app_id);
            }
        }

        Endpoint local  = { .addr = ev.local_addr, .port = ev.local_port };
        Endpoint remote = { .addr = ev.remote_addr, .port = ev.remote_port };
        SocketIdentity identity = {
            .local = local,
            .remote = remote,
            .protocol = Protocol.TCP,
            .family = ev.family
        };
        Socket new_socket = {
            .identity = identity,
            .state = SocketState.ESTABLISHED,
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

fn void? collect_network_snapshot(NetworkChannel* network_channel) {
    Clock start = clock::now();

    List{ulong} to_remove;
    to_remove.init(&network_channel.libc);
    defer to_remove.free();

    for (;;) {
        if (clock::now() - start >= network_channel.duration) break;
        NetworkInfo? info = get_process_info(network_channel);
        if (catch info) continue;
    }

    List{Socket} sockets_list;
    sockets_list.init(&network_channel.libc);
    defer sockets_list.free();

    List{TrafficStats} traffic_stats_list;
    traffic_stats_list.init(&network_channel.libc);
    defer traffic_stats_list.free();

    List{InspectInformation} inspect_info_list;
    inspect_info_list.init(&network_channel.libc);
    defer inspect_info_list.free();

    foreach (sock : network_channel.sock_map.value_iter()) {
        ulong sent = lookup_bytes(network_channel.network_stats.sent, sock.sock_cookie);
        ulong recv = lookup_bytes(network_channel.network_stats.recv, sock.sock_cookie);
        TrafficStats traffic_stats = {
            .sock_cookie = sock.sock_cookie,
            .sent = sent,
            .received = recv
        };
        InspectInformation inspect_info = {
            .remote_addr = sock.identity.remote.addr,
            .local_addr = sock.identity.local.addr,
            .local_port = sock.identity.local.port,
            .remote_port = sock.identity.remote.port,
            .hostname = "test",
            .cname = "test",
            .pid = sock.pid,
            .sock_state = sock.state,
            .traffic_stats = traffic_stats,
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
        io::printfn("removing sock_cookie: %d", cookie);
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
}

// TODO: Update later
struct InspectInformation {
    char[16] remote_addr;
    char[16] local_addr;
    ushort local_port;
    ushort remote_port;
    String hostname;
    String cname;
    uint pid;
    SocketState sock_state;
    TrafficStats traffic_stats;
}

struct NetworkSnapshot {
    HashMap{Application, ulong} app;
    List{Socket} sock;
    List{TrafficStats} traffic_stats;
    List{InspectInformation} information;
}

fn void? snapshot_loop(NetworkChannel* network_channel) {
    for (;;) {
        if (catch collect_network_snapshot(network_channel)) return;
    }
}

fn InspectInformation fetch_inspect_information(Allocator allocator, Socket* sock) {
    abort("not impl");
}
