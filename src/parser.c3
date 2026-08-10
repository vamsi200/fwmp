module parser;
import linsys;
import std::io;

fn void return_per_process_conn() => @pool() {
    int[] proc = process::list_pids(tmem)!!;
    foreach (p: proc){
      Connection[] con = process::connections(tmem, p)!!;
      if (con.len <= 0) continue;
      io::printn(p);
      foreach (c: con) io::printn(c);
    }

    // int[] pc = process::list_pids(tmem)!!;
    // foreach (p: pc) {
    // }
}
