module fetch;
import std::io;
import libbpf;
import linsys;
import std::collections::list;
import std::collections::map;
import std::thread::channel;

const ushort AF_INET  = 2;
const ushort AF_INET6 = 10;

struct Application {
    String name;
    String executable;
}

fn uint Application.hash(Application self) {
    uint h = self.name.hash();
    uint e = self.executable.hash();
    h ^= e;

    return h;
}

fn bool Application.equals(Application self, Application other) {
    return self.name == other.name && self.executable == other.executable;
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
    // Maybe{DnsInfo} dns;
    // 
    // Maybe{TlsInfo} tls;
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
    // AppId app_id;
    Endpoint local;
    Endpoint remote;
    Protocol protocol;
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

    return { .cookie = cookie, .sent = sent, .received = recv };
}

struct TrafficStats {
    ulong cookie;
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

fn int sock_bytes_sent_callback(void* ctx, void* data, usz size) {
    // RingBufContext* context = ctx;
    // if (size != Event::size) return 0;
    // 
    // Event event;
    // mem::copy(&event, data, Event::size);
    // context.events.push(event);
    // context.has_value = true;
    return 0;
}

fn int sock_bytes_recv_callback(void* ctx, void* data, usz size) {
    // RingBufContext* context = ctx;
    // if (size != Event::size) return 0;
    // 
    // Event event;
    // mem::copy(&event, data, Event::size);
    // context.events.push(event);
    // context.has_value = true;
    return 0;
}

struct NetworkChannel {
    LibcAllocator libc;
    BufferedChannel{Event}* channel;
    int map_fd;
    RingBufContext* ring_buf_ctx;
    RingBuffer* rb;
    NetworkStats network_stats;
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
    Application application;
    Event event;
}

fn Event? get_process_info(
    NetworkChannel* recv,
    HashMap{Application, ulong}* application,
    HashMap{ulong, Socket}* sockets,
    ulong app_id
) {
    LibcAllocator libc;

    NetworkInfo ni = { };

    @pool_init(&libc, 8192) {
        Event? ev = recv.channel.try_pop();

        if (catch ev) return EVENT_NOT_FOUND_ERROR~;

        if (ev.event_type == EventType.CLOSE) {
            sockets.remove(ev.sock_cookie);
        }

        Socket*? existing = sockets.get_ref(ev.sock_cookie);

        if (@ok(existing)) return EXISTING_SOCKET~;

        ProcessInfo pi = linsys::process::info(tmem, (int)ev.pid) ?? { };

        Application app = { .name = pi.process.name, .executable = pi.exe_path };

        if (!application.has_key(app)) {
            app_id += 1;
            application.set(app, app_id);
        }

        Endpoint local = { .addr = ev.local_addr, .port = ev.local_port };

        Endpoint remote = { .addr = ev.remote_addr, .port = ev.remote_port };

        SocketIdentity identity = { .local = local, .remote = remote, .protocol = Protocol.TCP };

        Socket new_socket = {
            .identity = identity,
            .state = SocketState.ESTABLISHED,
            .sock_cookie = ev.sock_cookie,
        };

        sockets.set(ev.sock_cookie, new_socket);

        return ev;
    };
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
    NetworkStats* network_stats;
}

struct NetworkSnapshot {
    List{Application} app;
    List{Socket} sock;
    InspectInformation information;
}

fn void? collect_network_snapshot(NetworkChannel* network_channel) {
    // ulong is appid
    HashMap{Application, ulong} application;
    application.init(&network_channel.libc);
    defer application.free();

    // ulong is socket_id
    HashMap{ulong, Socket} sockets;
    sockets.init(&network_channel.libc);
    defer sockets.free();

    ulong id = 0;

    for (;;) {
        Event? ev = get_process_info(network_channel, &application, &sockets, id);
        if (catch ev) continue;
        // io::printn(ev);

        Socket*? sks = sockets.get_ref(ev.sock_cookie);
        if (catch sks) continue;

        ulong sent = lookup_bytes(network_channel.network_stats.sent, sks.sock_cookie);
        ulong recv = lookup_bytes(network_channel.network_stats.recv, sks.sock_cookie);

        io::printfn("cookie: %d", sks.sock_cookie);
        io::printfn("sent: %d, recv: %d", sent, recv);
    }
}

fn InspectInformation fetch_inspect_information(
    Allocator allocator,
    Socket* sock,
    NetworkChannel* channel
) {
    // TrafficStats? ts = channel.traffic_channel.try_pop();
    abort("not impl");
}
