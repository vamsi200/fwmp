module fetch;
import std::io;
import libbpf;
import std::collections::list;

const ushort AF_INET  = 2;
const ushort AF_INET6 = 10;

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

fn int ringbuf_callback(void* ctx, void* data, usz size) => @pool() {
    if (size != Event::size) return 0;

    Event* event = (Event*)data;

    io::printfn(
        "pid=%d tid=%d family=%d protocol=%d local_port=%d remote_port=%d",
        event.pid,
        event.tid,
        event.family,
        event.protocol,
        event.local_port,
        event.remote_port
    );

    String local_addr  = convert_ip(tmem, event.family, event.local_addr);
    String remote_addr = convert_ip(tmem, event.family, event.remote_addr);
    io::printn(local_addr);
    io::printn(remote_addr);

    return 0;
}

fn void fetch_data_from_ebpf() => @pool() {
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

    RingBuffer* rb = libbpf::ring_buffer__new(map_fd, &ringbuf_callback, null, null);

    assert (rb != null);

    while (true) {
        int ret = libbpf::ring_buffer__poll(rb, 100);

        if (ret < 0) {
            io::printfn("poll error: %d", ret);
            break;
        }
    }

    foreach (link : links) {
        libbpf::bpf_link__destroy(link);
    }

    libbpf::ring_buffer__free(rb);
    libbpf::bpf_object__close(obj);
}
