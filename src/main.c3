module fwmp;
import std::io;
import clay;
import raylib6;
import std::thread;
import parser;
import libbpf;
import fetch;
import std::thread::channel;

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

  NetworkChannel nc = {};
  nc.channel = channel::create_buffered(tmem, 1024*1024)!!;
  defer nc.channel.destroy();

  t_1.create((ThreadFn)&fetch::fetch_data_from_ebpf, &nc)!!;
  t_2.create((ThreadFn)&fetch::get_process_info, &nc)!!;

  t_1.join()!!;
  t_2.join()!!;

  nc.channel.close();
}
