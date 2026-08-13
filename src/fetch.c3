module fetch;
import std::io;
import libbpf;
import linsys;
import std::collections::list;
import std::thread::channel;

const ushort AF_INET  = 2;
const ushort AF_INET6 = 10;

struct Application {
  uint id;
  String name;
  String executable;
  List {uint} processes;
}

enum EventType{
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
    BufferedChannel{Event}* channel;
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

        BpfMap* map = libbpf::bpf_object__find_map_by_name(obj, "events");

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

    @pool_init(&libc, 8192) {
        for (;;) {
            Event? ev       = recv.channel.try_pop();
            if (catch ev) continue;
            ProcessInfo pi = linsys::process::info(tmem, (int)ev.pid) ?? { };
            io::printn(pi);
        }
    };
}
