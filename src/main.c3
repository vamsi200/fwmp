module fwmp;
import std::io;
import clay;
import raylib6;
import std::thread;
import parser;
import libbpf;

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
libbpf::BpfObject* obj = libbpf::bpf_object__open("/home/vamsi/scripts/fwmp/bpf/fwmp.bpf.o");
    ZString name = libbpf::bpf_object__name(obj);
    io::printfn("opened object: %s", name);

    libbpf::bpf_object__close(obj);

  // parser::return_per_process_conn();
//   rl::init_window(1024, 768, "Test");
//
// 		clay::begin_layout();
//     ClayRenderCommandArray cmds = clay::end_layout(rl::get_frame_time());
//
// while (!rl::window_should_close()) {
//
//     clay::begin_layout();
//
//     layout();
//
//     // ClayRenderCommandArray cmds =
//         // clay::end_layout(...);
//
//     rl::begin_drawing();
//
//     rl::clear_background(rl::RAYWHITE);
//
//     // render_clay(cmds);
//
//     rl::end_drawing();
// }
//
// 	defer rl::close_window();;

}
