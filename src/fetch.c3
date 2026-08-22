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
    SocketId id;

    SocketIdentity identity;

    SocketState state;

    TrafficStats stats;

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
    AppId app;
    Endpoint local;
    Endpoint remote;
    Protocol protocol;
}

struct Endpoint {
    char[16] addr;
    ushort port;
}

struct TrafficStats {
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
    BufferedChannel{Event}* channel;
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
        BpfObject* obj = libbpf::bpf_object__open("/home/vamsi/scripts/fwmp/bpf/fwmp.bpf.o");
        if (obj == null) {
            io::printn("failed to open BPF object");
            return;
        }

        int err = libbpf::bpf_object__load(obj);
        if (err != 0) {
            io::printfn("failed to load BPF object: %d", err);
            libbpf::bpf_object__close(obj);
            return;
        }

        List{BpfLink*} links;
        links.init(tmem);
        BpfProgram* prog = null;
        RingBufContext ring_buf_ctx;

        while ((prog = libbpf::bpf_object__next_program(obj, prog)) != null) {
            ZString section = libbpf::bpf_program__section_name(prog);
            if (section == null) continue;
            io::printfn("found program: %s", section);
            BpfLink* link = libbpf::bpf_program__attach(prog);
            if (link == null) {
                io::printfn("failed to attach %s", section);
                foreach (existing : links) {
                    libbpf::bpf_link__destroy(existing);
                }
                libbpf::bpf_object__close(obj);
                return;
            }
            links.push(link);
            io::printfn("attached %s", section);
        }

        BpfMap* map             = libbpf::bpf_object__find_map_by_name(obj, "events");
        BpfMap* sock_bytes_sent = libbpf::bpf_object__find_map_by_name(obj, "sock_bytes_sent");
        BpfMap* sock_bytes_recv = libbpf::bpf_object__find_map_by_name(obj, "sock_bytes_recv");


        int map_fd = libbpf::bpf_map__fd(map);
        RingBuffer* rb = libbpf::ring_buffer__new(map_fd, &ringbuf_callback, &ring_buf_ctx, null);

        assert (rb != null);
        while (true) {
            int ret = libbpf::ring_buffer__poll(rb, 100);
            if (ret < 0) {
                io::printfn("poll error: %d", ret);
                break;
            }

            foreach (event : ring_buf_ctx.events) {
                io::printn(event);
                ulong sent = lookup_bytes(sock_bytes_sent, event.sock_cookie);
                ulong recv = lookup_bytes(sock_bytes_recv, event.sock_cookie);
                io::printfn("cookie: %d, sent: %d, recv: %d", event.sock_cookie, sent, recv);
                if (!@ok(nc.channel.try_push(event))) io::printn("Failed to send event");
            }

            ring_buf_ctx.events.clear();
        }

        foreach (link : links) {
            libbpf::bpf_link__destroy(link);
        }

        libbpf::ring_buffer__free(rb);
        libbpf::bpf_object__close(obj);
    };
}

fn void get_process_info(NetworkChannel* recv) {
    LibcAllocator libc;

    List{uint} pids = { };
    pids.init(&libc);
    defer pids.free();

    List{SocketId} sock_id = { };
    sock_id.init(&libc);
    defer sock_id.free();

    List{Socket} sock = { };
    sock.init(&libc);
    defer sock.free();

    HashMap{Application, ulong} application;
    application.init(&libc);
    defer application.free();

    ulong app_id = 0;
    @pool_init(&libc, 8192) {
        // for (;;) {
        // Event? ev = recv.channel.try_pop();
        // if (catch ev) continue;
        // ProcessInfo pi  = linsys::process::info(tmem, (int)ev.pid) ?? { };
        // Application app = { .name = pi.process.name, .executable = pi.exe_path };
        // if (!(application.has_key(app))) {
        //     app_id += 1;
        //     application.set(app, app_id);
        // }
        // 
        // sock_id.push(ev.sock_cookie);
        // pids.push(ev.pid);
        // 
        // 
        // Endpoint ep_local  = { .addr = ev.local_addr, .port = ev.local_port };
        // Endpoint ep_remote = { .addr = ev.remote_addr, .port = ev.remote_port };
        // SocketIdentity si = {
        //     .app = app_id,
        //     .local = ep_local,
        //     .remote = ep_remote,
        //     .protocol = Protocol.TCP
        // };
        // TrafficStats ts = { .sent = 0, .received = 0 };
        // 
        // Socket sk = {
        //     .id = ev.sock_cookie,
        //     .identity = si,
        //     .state = SocketState.ESTABLISHED,
        //     .stats = ts
        // };
        // io::printn(sk);
        // }
    };
}

fn Application fetch_inspect_information(Allocator allocator, Socket* sock) {
    abort("");
}
