module fwmp;
import std::io;
import clay;
import raylib6;
import std::thread;
import parser;
import libbpf;
import fetch;
import std::thread::channel;
import std::collections::list;

const clay::ClayColor COLOR_LIGHT  = { 224, 215, 210, 255 };
const clay::ClayColor COLOR_RED    = { 168, 66, 28, 255 };
const clay::ClayColor COLOR_ORANGE = { 225, 138, 50, 255 };

// fn void on_error(ClayErrorData error) {
//     io::printfn(
//         "clay error (type=%d): %.*s",
//         (int)error.error_type,
//         error.error_text.length,
//         error.error_text.chars
//     );
// }
// 
// fn void layout() {
//   clay::@ui_with_id(
//     clay::@id("testc"),
//     {
//       .layout = {
//           .sizing = {.width = clay::sizing_grow(), .height = clay::sizing_grow()},
//           .padding = clay::padding_all(15),
//           .child_gap = 15
//         },
//         .background_color = COLOR_LIGHT
//   }
//   ){
// 
//     };
// }


fn void main(String[] args) {
    Thread t_1, t_2;

    NetworkChannel nc = { };
    LibcAllocator libc;

    nc.channel = channel::create_buffered(tmem, 1024 * 1024)!!;
    nc.libc = libc;

    defer nc.channel.destroy();

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
    links.init(&libc);
    defer links.free();

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

    if (map == null || sock_bytes_sent == null || sock_bytes_recv == null) {
        io::printn("failed to find required BPF maps");

        foreach (link : links) {
            libbpf::bpf_link__destroy(link);
        }

        libbpf::bpf_object__close(obj);
        return;
    }

    int map_fd = libbpf::bpf_map__fd(map);

    RingBuffer* rb = libbpf::ring_buffer__new(
        map_fd,
        &fetch::ringbuf_callback,
        &ring_buf_ctx,
        null
    );

    if (rb == null) {
        io::printn("failed to create ring buffer");

        foreach (link : links) {
            libbpf::bpf_link__destroy(link);
        }

        libbpf::bpf_object__close(obj);
        return;
    }

    nc.map_fd = map_fd;
    nc.ring_buf_ctx = &ring_buf_ctx;
    nc.rb = rb;
    nc.network_stats.sent = sock_bytes_sent;
    nc.network_stats.recv = sock_bytes_recv;

    t_1.create((ThreadFn)&fetch::fetch_data_from_ebpf, &nc)!!;
    t_2.create((ThreadFn)&fetch::collect_network_snapshot, &nc)!!;

    t_1.join()!!;
    t_2.join()!!;

    foreach (link : links) {
        libbpf::bpf_link__destroy(link);
    }

    libbpf::ring_buffer__free(rb);
    libbpf::bpf_object__close(obj);

    nc.channel.close();
}
