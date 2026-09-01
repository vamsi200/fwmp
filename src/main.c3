module fwmp;
import std::io;
import clay;
import raylib6::rl;
import std::thread;
import libbpf;
import fetch;
import std::thread::channel;
import std::collections::list;
import std::time;
import std::math::random;
import std::collections::map;
import linsys;
import libc;

const clay::ClayColor COLOR_BG        = { 6, 8, 10, 255 };
const clay::ClayColor COLOR_BORDER    = { 28, 58, 38, 255 };
const clay::ClayColor COLOR_DIM       = { 42, 107, 69, 255 };
const clay::ClayColor COLOR_TEXT      = { 62, 240, 124, 255 };
const clay::ClayColor COLOR_ACTIVE_BG = { 18, 39, 26, 255 };
const clay::ClayColor COLOR_ACTIVE_TX = { 234, 255, 156, 255 };
const clay::ClayColor COLOR_WARN      = { 224, 169, 76, 255 };
const clay::ClayColor COLOR_NONE      = { 0, 0, 0, 0 };

const clay::ClayColor COLOR_ACCENT      = { 100, 181, 246, 255 };
const clay::ClayColor COLOR_GREEN       = { 76, 175, 80, 255 };
const clay::ClayColor COLOR_YELLOW      = { 255, 220, 79, 255 };
const clay::ClayColor COLOR_BLUE        = { 66, 165, 245, 255 };
const clay::ClayColor COLOR_SELECTED    = { 100, 181, 246, 38 };
const clay::ClayColor COLOR_HOVER       = { 255, 255, 255, 20 };
const clay::ClayColor COLOR_CARD_BG     = { 255, 255, 255, 8 };
const clay::ClayColor COLOR_KEY_BG      = { 255, 255, 255, 20 };
const clay::ClayColor COLOR_BADGE_BG    = { 255, 255, 255, 20 };
const clay::ClayColor COLOR_TRANSPARENT = { 0, 0, 0, 0 };

RLFont g_font;

const int MAX_APPS  = 32;
const int MAX_SOCKS = 64;

long g_retention_secs    = 100;
long g_fetch_interval_ms = 100;

Application[MAX_APPS] g_app_list;
ulong[MAX_APPS] g_app_ids;
int g_app_count = 0;

Socket[MAX_SOCKS] g_sock_list;
int g_sock_count = 0;

NetworkSnapshot g_snapshot;
bool g_has_snapshot = false;

String g_focus = "apps";

int g_app_idx  = 0;
int g_sock_idx = 0;

fn void poll_snapshot(NetworkChannel* channel) {
    NetworkSnapshot? snap = channel.snapshot_channel.try_pop();
    if (try snap) {
        if (g_has_snapshot) {
            g_snapshot.sock.free();
            g_snapshot.traffic_stats.free();
            g_snapshot.information.free();
        }
        g_snapshot = snap;
        g_has_snapshot = true;
    }
}

macro clay::ClayPadding padding_xy(ushort x, ushort y) => { x, x, y, y };

macro clay::ClayString cstr(String s) => clay::make_string(s);

macro clay::ClayTextElementConfig text_cfg(
    clay::ClayColor color,
    ushort size = 20
) => { .text_color = color, .font_size = size };

fn void row_text(String text, bool active, bool warn) {
    clay::ClayColor color = active ? COLOR_ACTIVE_TX : (warn ? COLOR_WARN : COLOR_DIM);
    clay::@ui(
        {
            .layout = {
                .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_fixed(18) },
                .padding = padding_xy(10, 2),
            },
            .background_color = active ? COLOR_ACTIVE_BG : COLOR_NONE,
        }
    ) {
        clay::@text(cstr(text), text_cfg(color));
    };
}

fn void panel_header(String text) {
    clay::@ui({ .layout = { .padding = padding_xy(0, 4) }, }) {
        clay::@text(cstr(text), text_cfg(COLOR_DIM));
    };
}

fn void inspect_line(String label, String value, bool highlight) {
    clay::@ui(
        {
            .layout = {
                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                .sizing = { .width = clay::sizing_grow() },
                .child_gap = 8,
            },
        }
    ) {
        clay::@text(cstr(label), text_cfg(COLOR_DIM));
        clay::@text(cstr(value), text_cfg(highlight ? COLOR_ACTIVE_TX : COLOR_TEXT));
    };
}

fn void row_text_id(clay::ClayElementId id, String text, bool active, bool warn) {
    clay::ClayColor color = active ? COLOR_ACTIVE_TX : (warn ? COLOR_WARN : COLOR_DIM);
    clay::@ui_with_id(
        id,
        {
            .layout = {
                .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_fixed(18) },
                .padding = padding_xy(4, 4),
                .child_alignment = {
                    .x = clay::ClayLayoutAlignmentX.LEFT,
                    .y = clay::ClayLayoutAlignmentY.CENTER
                },
            },
            .background_color = active ? COLOR_ACTIVE_BG : COLOR_NONE,
        }
    ) {
        clay::@text(cstr(text), text_cfg(color));
    };
}

fn String copy_da_string(String str, Allocator allocator) {
    if (str.ptr == null || str.len == 0) return "";
    return str.copy(allocator);
}

ulong g_selected_app_id = 0;
bool g_has_selected_app = false;


fn String get_state(SocketState state) {
    switch (state) {
        case SocketState.ESTABLISHED:
            return "ESTB";
        case SocketState.SYN_SENT:
            return "SYNS";
        case SocketState.SYN_RECV:
            return "SYNR";
        case SocketState.FIN_WAIT1:
            return "FW1";
        case SocketState.FIN_WAIT2:
            return "FW2";
        case SocketState.TIME_WAIT:
            return "TWAIT";
        case SocketState.CLOSE:
            return "CLOSE";
        case SocketState.CLOSE_WAIT:
            return "CWT";
        case SocketState.LAST_ACK:
            return "LACK";
        case SocketState.LISTEN:
            return "LISTEN";
        case SocketState.CLOSING:
            return "CLOS";
        default:
            return "UNKN";
    }
}

fn ClayColor get_state_color(SocketState state) {
    switch (state) {
        case SocketState.ESTABLISHED:
            return COLOR_GREEN;
        case SocketState.TIME_WAIT:
        case SocketState.FIN_WAIT1:
        case SocketState.FIN_WAIT2:
            return COLOR_WARN;
        case SocketState.SYN_SENT:
        case SocketState.SYN_RECV:
            return COLOR_ACCENT;
        case SocketState.LISTEN:
            return COLOR_BLUE;
        case SocketState.CLOSE:
        case SocketState.CLOSE_WAIT:
        case SocketState.LAST_ACK:
        case SocketState.CLOSING:
            return COLOR_DIM;
        default:
            return COLOR_DIM;
    }
}

macro void footer_key(String key, String action, uint index) {
    clay::@ui_with_id(
        clay::@id_i("footer-key", index),
        {
            .layout = {
                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                .sizing = { .width = clay::sizing_fixed(0), .height = clay::sizing_fixed(0) },
                .padding = { .left = 0, .right = 0, .top = 0, .bottom = 0 },
                .child_gap = 4,
            },
        }
    ) {
        clay::@text(clay::@string(key), text_cfg(COLOR_TEXT, 20));
        clay::@text(clay::@string(action), text_cfg(COLOR_DIM, 20));
    };
}

fn String format_bytes(usz bytes) {
    String[] units = { "B", "KB", "MB", "GB", "TB" };

    float size = (float)bytes;
    usz unit   = 0;

    while (size >= 1024.0f && unit < units.len - 1) {
        size /= 1024.0f;
        unit++;
    }

    return string::tformat("%.1f %s", size, units[unit]);
}

fn void layout(NetworkChannel* channel, bool mouse_clicked) {
    poll_snapshot(channel);
    if (!g_has_snapshot) {
        return;
    }

    g_app_count = 0;
    g_snapshot.app.@each(; Application app, ulong id) {
        g_app_list[g_app_count] = app;
        g_app_ids[g_app_count] = id;
        g_app_count++;
    };

    if (!g_has_selected_app && g_app_count > 0) {
        g_selected_app_id = g_app_ids[0];
        g_has_selected_app = true;
    }

    g_app_idx = 0;
    for (int i = 0; i < g_app_count; i++) {
        if (g_app_ids[i] == g_selected_app_id) {
            g_app_idx = i;
            break;
        }
    }

    ulong selected_app_id = g_app_count > 0 ? g_app_ids[g_app_idx] : 0;

    g_sock_count = 0;
    foreach (s : g_snapshot.sock) {
        if (s.app_id != selected_app_id) continue;
        if (g_sock_count >= MAX_SOCKS) break;
        g_sock_list[g_sock_count] = s;
        g_sock_count++;
    }
    if (g_sock_idx >= g_sock_count) g_sock_idx = 0;

    Socket* sock             = g_sock_count > 0 ? &g_sock_list[g_sock_idx] : null;
    TrafficStats* stats      = null;
    InspectInformation* info = null;
    if (sock) {
        foreach (&ts : g_snapshot.traffic_stats) {
            if (ts.sock_cookie == sock.sock_cookie) {
                stats = ts;
                break;
            }
        }
        foreach (&ii : g_snapshot.information) {
            if (ii.traffic_stats.sock_cookie == sock.sock_cookie) {
                info = ii;
                break;
            }
        }
    }

    clay::@ui_with_id(
        clay::@id("fwmp-root"),
        {
            .layout = {
                .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_grow() },
                .padding = clay::padding_all(16),
                .child_gap = 8,
            },
            .background_color = COLOR_BG,
            .border = {
                .color = COLOR_BORDER,
                .width = { .left = 1, .right = 1, .top = 1, .bottom = 1, .between_children = 0 },
            },
            .corner_radius = {
                .top_left = 8,
                .top_right = 8,
                .bottom_left = 8,
                .bottom_right = 8
            },
        }
    ) {
        clay::@ui_with_id(
            clay::@id("titlebar"),
            {
                .layout = {
                    .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                    .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_fixed(28) },
                    .padding = { .left = 0, .right = 0, .top = 0, .bottom = 6 },
                    .child_alignment = {
                        .x = clay::ClayLayoutAlignmentX.CENTER,
                        .y = clay::ClayLayoutAlignmentY.CENTER
                    },
                },
                .border = { .color = COLOR_BORDER, .width = { .bottom = 1 }, },
            }
        ) {
            clay::@text(clay::@string("fwmp v0.1"), text_cfg(COLOR_DIM, 20));

            clay::@ui_with_id(
                clay::@id("title-spacer"),
                {
                    .layout = {
                        .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                        .sizing = {
                            .width = clay::sizing_grow(),
                            .height = clay::sizing_fixed(0)
                        },
                    },
                }
            ) {
            };

            clay::@ui_with_id(
                clay::@id("settings-panel"),
                {
                    .layout = {
                        .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                        .sizing = {
                            .width = clay::sizing_fixed(0),
                            .height = clay::sizing_fixed(0)
                        },
                        .child_gap = 16,
                        .child_alignment = {
                            .x = clay::ClayLayoutAlignmentX.CENTER,
                            .y = clay::ClayLayoutAlignmentY.CENTER
                        },
                    },
                }
            ) {
                clay::@ui_with_id(
                    clay::@id("retention-control"),
                    {
                        .layout = {
                            .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                            .sizing = {
                                .width = clay::sizing_fixed(0),
                                .height = clay::sizing_fixed(0)
                            },
                            .child_gap = 6,
                            .child_alignment = {
                                .x = clay::ClayLayoutAlignmentX.CENTER,
                                .y = clay::ClayLayoutAlignmentY.CENTER
                            },
                        },
                    }
                ) {
                    clay::@text(clay::@string("ret:"), text_cfg(COLOR_DIM, 20));

                    clay::@text(
                        clay::@string(string::tformat("%ds", g_retention_secs)),
                        text_cfg(COLOR_TEXT, 20)
                    );

                    clay::@ui_with_id(
                        clay::@id("retention-dec"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                .sizing = {
                                    .width = clay::sizing_fixed(20),
                                    .height = clay::sizing_fixed(18)
                                },
                                .padding = { .left = 2, .right = 2, .top = 1, .bottom = 1 },
                                .child_alignment = {
                                    .x = clay::ClayLayoutAlignmentX.CENTER,
                                    .y = clay::ClayLayoutAlignmentY.CENTER
                                },
                            },
                            .background_color = clay::pointer_over(
                                clay::@id("retention-dec")
                            ) ? COLOR_HOVER : COLOR_TRANSPARENT,
                            .border = {
                                .color = COLOR_BORDER,
                                .width = {
                                    .left = 1,
                                    .right = 0,
                                    .top = 1,
                                    .bottom = 1,
                                    .between_children = 0
                                },
                            },
                            .corner_radius = {
                                .top_left = 3,
                                .top_right = 0,
                                .bottom_left = 3,
                                .bottom_right = 0
                            },
                        }
                    ) {
                        clay::@text(clay::@string("-"), text_cfg(COLOR_TEXT, 20));
                    };

                    clay::@ui_with_id(
                        clay::@id("retention-inc"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                .sizing = {
                                    .width = clay::sizing_fixed(20),
                                    .height = clay::sizing_fixed(18)
                                },
                                .padding = { .left = 2, .right = 2, .top = 1, .bottom = 1 },
                                .child_alignment = {
                                    .x = clay::ClayLayoutAlignmentX.CENTER,
                                    .y = clay::ClayLayoutAlignmentY.CENTER
                                },
                            },
                            .background_color = clay::pointer_over(
                                clay::@id("retention-inc")
                            ) ? COLOR_HOVER : COLOR_TRANSPARENT,
                            .border = {
                                .color = COLOR_BORDER,
                                .width = {
                                    .left = 0,
                                    .right = 1,
                                    .top = 1,
                                    .bottom = 1,
                                    .between_children = 0
                                },
                            },
                            .corner_radius = {
                                .top_left = 0,
                                .top_right = 3,
                                .bottom_left = 0,
                                .bottom_right = 3
                            },
                        }
                    ) {
                        clay::@text(clay::@string("+"), text_cfg(COLOR_TEXT, 20));
                    };
                };

                clay::@ui_with_id(
                    clay::@id("fetch-control"),
                    {
                        .layout = {
                            .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                            .sizing = {
                                .width = clay::sizing_fixed(0),
                                .height = clay::sizing_fixed(0)
                            },
                            .child_gap = 6,
                            .child_alignment = {
                                .x = clay::ClayLayoutAlignmentX.CENTER,
                                .y = clay::ClayLayoutAlignmentY.CENTER
                            },
                        },
                    }
                ) {
                    clay::@text(clay::@string("fetch:"), text_cfg(COLOR_DIM, 20));

                    clay::@text(
                        clay::@string(string::tformat("%dms", g_fetch_interval_ms)),
                        text_cfg(COLOR_TEXT, 20)
                    );

                    clay::@ui_with_id(
                        clay::@id("fetch-dec"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                .sizing = {
                                    .width = clay::sizing_fixed(20),
                                    .height = clay::sizing_fixed(18)
                                },
                                .padding = { .left = 2, .right = 2, .top = 1, .bottom = 1 },
                                .child_alignment = {
                                    .x = clay::ClayLayoutAlignmentX.CENTER,
                                    .y = clay::ClayLayoutAlignmentY.CENTER
                                },
                            },
                            .background_color = clay::pointer_over(
                                clay::@id("fetch-dec")
                            ) ? COLOR_HOVER : COLOR_TRANSPARENT,
                            .border = {
                                .color = COLOR_BORDER,
                                .width = {
                                    .left = 1,
                                    .right = 0,
                                    .top = 1,
                                    .bottom = 1,
                                    .between_children = 0
                                },
                            },
                            .corner_radius = {
                                .top_left = 3,
                                .top_right = 0,
                                .bottom_left = 3,
                                .bottom_right = 0
                            },
                        }
                    ) {
                        clay::@text(clay::@string("-"), text_cfg(COLOR_TEXT, 14));
                    };

                    clay::@ui_with_id(
                        clay::@id("fetch-inc"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                .sizing = {
                                    .width = clay::sizing_fixed(20),
                                    .height = clay::sizing_fixed(18)
                                },
                                .padding = { .left = 2, .right = 2, .top = 1, .bottom = 1 },
                                .child_alignment = {
                                    .x = clay::ClayLayoutAlignmentX.CENTER,
                                    .y = clay::ClayLayoutAlignmentY.CENTER
                                },
                            },
                            .background_color = clay::pointer_over(
                                clay::@id("fetch-inc")
                            ) ? COLOR_HOVER : COLOR_TRANSPARENT,
                            .border = {
                                .color = COLOR_BORDER,
                                .width = {
                                    .left = 0,
                                    .right = 1,
                                    .top = 1,
                                    .bottom = 1,
                                    .between_children = 0
                                },
                            },
                            .corner_radius = {
                                .top_left = 0,
                                .top_right = 3,
                                .bottom_left = 0,
                                .bottom_right = 3
                            },
                        }
                    ) {
                        clay::@text(clay::@string("+"), text_cfg(COLOR_TEXT, 14));
                    };

                    if (mouse_clicked) {
                        if (clay::pointer_over(clay::@id("retention-dec"))) {
                            g_retention_secs = max(g_retention_secs - 1, 1);
                            channel.retention = set_retention(g_retention_secs);
                        }
                        if (clay::pointer_over(clay::@id("retention-inc"))) {
                            g_retention_secs = min(g_retention_secs + 1, 60);
                            channel.retention = set_retention(g_retention_secs);
                        }

                        if (clay::pointer_over(clay::@id("fetch-dec"))) {
                            g_fetch_interval_ms = max(g_fetch_interval_ms - 10, 10);
                            channel.fetch_interval = set_fetch_interval(g_fetch_interval_ms);
                        }
                        if (clay::pointer_over(clay::@id("fetch-inc"))) {
                            g_fetch_interval_ms = min(g_fetch_interval_ms + 10, 1000);
                            channel.fetch_interval = set_fetch_interval(g_fetch_interval_ms);
                        }
                    }
                };
            };
        };

        clay::@ui_with_id(
            clay::@id("cols"),
            {
                .layout = {
                    .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                    .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_grow() },
                    .child_gap = 0,
                },
            }
        ) {
            clay::@ui_with_id(
                clay::@id("col-apps"),
                {
                    .layout = {
                        .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                        .sizing = {
                            .width = clay::sizing_fixed(200),
                            .height = clay::sizing_grow()
                        },
                        .padding = { .left = 14, .right = 14, .top = 4, .bottom = 4 },
                        .child_gap = 2,
                    },
                    .border = { .color = COLOR_BORDER, .width = { .right = 1 }, },
                }
            ) {
                clay::@text(clay::@string("[ apps ]"), text_cfg(COLOR_DIM, 20));

                clay::ClayElementId apps_list_id = clay::@id("apps-list");
                clay::_open_element_with_id(apps_list_id);
                clay::ClayVector2 scroll_offset = clay::get_scroll_offset();
                clay::_configure_open_element(
                    {
                        .layout = {
                            .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                            .sizing = {
                                .width = clay::sizing_grow(),
                                .height = clay::sizing_grow()
                            },
                            .child_gap = 0,
                            .padding = { .top = 4, .bottom = 8 },
                        },
                        .clip = { .vertical = true, .child_offset = scroll_offset },
                    }
                );

                for (int i = 0; i < g_app_count; i++) {
                    clay::ClayElementId id = clay::@id_i("app-row", (uint)i);
                    bool is_selected       = (i == g_app_idx);
                    bool is_focused        = (g_focus == "apps" && is_selected);

                    clay::_open_element_with_id(id);
                    clay::_configure_open_element(
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                .sizing = {
                                    .width = clay::sizing_grow(),
                                    .height = clay::sizing_fixed(22)
                                },
                                .padding = { .left = 4, .right = 4, .top = 2, .bottom = 2 },
                                .child_gap = 4,
                            },
                            .background_color = is_focused ? COLOR_SELECTED : COLOR_TRANSPARENT,
                        }
                    );

                    clay::@text(
                        clay::@string(is_focused ? ">> " : ""),
                        text_cfg(is_focused ? COLOR_ACTIVE_TX : COLOR_DIM, 20)
                    );

                    clay::@text(
                        clay::@string(g_app_list[i].name),
                        text_cfg(is_focused ? COLOR_ACTIVE_TX : COLOR_DIM, 20)
                    );

                    clay::_close_element();

                    if (mouse_clicked && clay::pointer_over(id)) {
                        g_app_idx = i;
                        g_selected_app_id = g_app_ids[i];
                        g_sock_idx = 0;
                        g_focus = "apps";
                    }
                }
                clay::_close_element();
            };

            clay::ClayElementId sockets_id = clay::@id("col-sockets");
            clay::_open_element_with_id(sockets_id);
            clay::ClayVector2 scroll_offset_socks = clay::get_scroll_offset();
            clay::_configure_open_element(
                {
                    .layout = {
                        .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                        .sizing = {
                            .width = clay::sizing_fixed(600),
                            .height = clay::sizing_grow()
                        },
                        .padding = { .left = 14, .right = 14, .top = 4, .bottom = 4 },
                        .child_gap = 6,
                    },
                    .border = { .color = COLOR_BORDER, .width = { .right = 1 }, },
                    .clip = { .vertical = true, .child_offset = scroll_offset_socks },
                }
            );

            String app_name     = g_app_count > 0 ? g_app_list[g_app_idx].name : "—";
            String header_title = string::tformat("[ sockets: %s (%d) ]", app_name, g_sock_count);
            clay::@text(clay::@string(header_title), text_cfg(COLOR_DIM, 20));

            for (int i = 0; i < g_sock_count; i++) {
                Socket s               = g_sock_list[i];
                clay::ClayElementId id = clay::@id_i("sock-row", (uint)i);
                bool is_selected       = (i == g_sock_idx);
                bool is_focused        = (g_focus == "sockets" && is_selected);
                bool is_established    = (s.state == SocketState.ESTABLISHED);

                clay::_open_element_with_id(id);
                clay::_configure_open_element(
                    {
                        .layout = {
                            .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                            .sizing = {
                                .width = clay::sizing_grow(),
                                .height = clay::sizing_fixed(26)
                            },
                            .padding = { .left = 4, .right = 4, .top = 3, .bottom = 3 },
                            .child_gap = 4,
                        },
                        .background_color = is_focused ? COLOR_SELECTED : COLOR_TRANSPARENT,
                    }
                );

                clay::@text(
                    clay::@string(is_focused ? ">> " : ""),
                    text_cfg(is_focused ? COLOR_ACTIVE_TX : COLOR_DIM, 20)
                );

                String addr = string::tformat(
                    "[%s]:%d",
                    fetch::convert_ip(tmem, s.identity.family, s.identity.remote.addr),
                    s.identity.remote.port
                );
                clay::@text(
                    clay::@string(addr),
                    text_cfg(is_focused ? COLOR_ACTIVE_TX : COLOR_DIM, 20)
                );

                clay::@ui_with_id(
                    clay::@id_i("sock-spacer", (uint)i),
                    {
                        .layout = {
                            .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                            .sizing = {
                                .width = clay::sizing_grow(),
                                .height = clay::sizing_fixed(0)
                            },
                        },
                    }
                ) {
                };

                String state_short    = get_state(s.state);
                ClayColor state_color = get_state_color(s.state);
                clay::@text(clay::@string(state_short), text_cfg(state_color, 20));

                clay::_close_element();

                if (mouse_clicked && clay::pointer_over(id)) {
                    g_sock_idx = i;
                    g_focus = "sockets";
                }
            }

            clay::_close_element();

            clay::@ui_with_id(
                clay::@id("col-inspect"),
                {
                    .layout = {
                        .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                        .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_grow() },
                        .padding = { .left = 14, .right = 14, .top = 4, .bottom = 4 },
                        .child_gap = 2,
                    },
                }
            ) {
                clay::@text(clay::@string("[ inspect ]"), text_cfg(COLOR_DIM, 20));

                if (sock && info) {
                    clay::@ui_with_id(
                        clay::@id("inspect-content"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                .sizing = {
                                    .width = clay::sizing_grow(),
                                    .height = clay::sizing_grow()
                                },
                                .padding = { .top = 4, .bottom = 0 },
                                .child_gap = 2,
                            },
                        }
                    ) {
                        clay::@ui_with_id(
                            clay::@id("process-section"),
                            {
                                .layout = {
                                    .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                    .sizing = {
                                        .width = clay::sizing_grow(),
                                        .height = clay::sizing_fixed(0)
                                    },
                                    .padding = { .top = 4, .bottom = 0 },
                                    .child_gap = 5,
                                },
                            }
                        ) {
                            clay::@text(clay::@string("Process"), text_cfg(COLOR_ACCENT, 20));

                            clay::@ui_with_id(
                                clay::@id("process-divider"),
                                {
                                    .layout = {
                                        .layout_direction = clay::ClayLayoutDirection
                                            .LEFT_TO_RIGHT,
                                        .sizing = {
                                            .width = clay::sizing_grow(),
                                            .height = clay::sizing_fixed(1)
                                        },
                                    },
                                    .background_color = COLOR_BORDER,
                                }
                            ) {
                            };

                            inspect_line("pid", string::tformat("%d", info.pid), true);
                            inspect_line("ppid", string::tformat("%d", info.ppid), false);
                            inspect_line("name", info.process_name, true);
                            inspect_line("state", string::tformat("%s", info.state), false);
                            inspect_line("exe_path", info.exe_path, false);
                            inspect_line("cmdline", info.cmdline, false);
                            inspect_line("uid", string::tformat("%d", info.uid), false);
                        };

                        clay::@ui_with_id(
                            clay::@id("section-spacer"),
                            {
                                .layout = {
                                    .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                                    .sizing = {
                                        .width = clay::sizing_grow(),
                                        .height = clay::sizing_fixed(6)
                                    },
                                },
                            }
                        ) {
                        };

                        clay::@ui_with_id(
                            clay::@id("event-section"),
                            {
                                .layout = {
                                    .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                    .sizing = {
                                        .width = clay::sizing_grow(),
                                        .height = clay::sizing_fixed(0)
                                    },
                                    .child_gap = 5,
                                },
                            }
                        ) {
                            clay::@text(clay::@string("Event"), text_cfg(COLOR_ACCENT, 20));

                            clay::@ui_with_id(
                                clay::@id("event-divider"),
                                {
                                    .layout = {
                                        .layout_direction = clay::ClayLayoutDirection
                                            .LEFT_TO_RIGHT,
                                        .sizing = {
                                            .width = clay::sizing_grow(),
                                            .height = clay::sizing_fixed(1)
                                        },
                                        .padding = { .top = 2, .bottom = 2 },
                                    },
                                    .background_color = COLOR_BORDER,
                                }
                            ) {
                            };

                            inspect_line("cookie", string::tformat("%d", info.sock_cookie), true);
                            String remote_addr = string::tformat(
                                "[%s]:%d",
                                fetch::convert_ip(tmem, info.family, info.remote_addr),
                                info.remote_port
                            );
                            inspect_line("remote", remote_addr, true);

                            String local_addr = string::tformat(
                                "[%s]:%d",
                                fetch::convert_ip(tmem, 2, info.local_addr),
                                info.local_port
                            );
                            inspect_line("local", local_addr, false);

                            inspect_line("protocol", string::tformat("%s", info.protocol), false);
                            inspect_line("family", string::tformat("%d", info.family), false);

                            SocketState state    = info.sock_state;
                            String state_display = string::tformat("%s", state);
                            ClayColor state_color = (state
                                == SocketState.ESTABLISHED) ? COLOR_GREEN : COLOR_WARN;

                            clay::@ui_with_id(
                                clay::@id("inspect-state"),
                                {
                                    .layout = {
                                        .layout_direction = clay::ClayLayoutDirection
                                            .LEFT_TO_RIGHT,
                                        .sizing = {
                                            .width = clay::sizing_grow(),
                                            .height = clay::sizing_fixed(20)
                                        },
                                        .padding = {
                                            .left = 0,
                                            .right = 0,
                                            .top = 0,
                                            .bottom = 0
                                        },
                                        .child_gap = 6,
                                    },
                                }
                            ) {
                                clay::@text(clay::@string("state"), text_cfg(COLOR_DIM, 20));
                                clay::@text(clay::@string("["), text_cfg(COLOR_DIM, 20));
                                clay::@text(
                                    clay::@string(state_display),
                                    text_cfg(state_color, 20)
                                );
                                clay::@text(clay::@string("]"), text_cfg(COLOR_DIM, 20));
                            };

                            if (info.traffic_stats.sent > 0 || info.traffic_stats.received > 0) {
                                inspect_line("sent", format_bytes(info.traffic_stats.sent), false);

                                inspect_line(
                                    "recv",
                                    format_bytes(info.traffic_stats.received),
                                    false
                                );
                            }
                        };
                    };
                } else if (sock) {
                    clay::@ui_with_id(
                        clay::@id("inspect-content"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                .sizing = {
                                    .width = clay::sizing_grow(),
                                    .height = clay::sizing_grow()
                                },
                                .padding = { .top = 4, .bottom = 0 },
                                .child_gap = 2,
                            },
                        }
                    ) {
                        clay::@ui_with_id(
                            clay::@id("socket-section"),
                            {
                                .layout = {
                                    .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                    .sizing = {
                                        .width = clay::sizing_grow(),
                                        .height = clay::sizing_fixed(0)
                                    },
                                    .child_gap = 0,
                                },
                            }
                        ) {
                            clay::@text(clay::@string("Socket Info"), text_cfg(COLOR_ACCENT, 14));

                            clay::@ui_with_id(
                                clay::@id("socket-divider"),
                                {
                                    .layout = {
                                        .layout_direction = clay::ClayLayoutDirection
                                            .LEFT_TO_RIGHT,
                                        .sizing = {
                                            .width = clay::sizing_grow(),
                                            .height = clay::sizing_fixed(1)
                                        },
                                        .padding = { .top = 2, .bottom = 2 },
                                    },
                                    .background_color = COLOR_BORDER,
                                }
                            ) {
                            };

                            inspect_line(
                                "remote",
                                string::tformat(
                                    "[%s]:%d",
                                    fetch::convert_ip(
                                        tmem,
                                        sock.identity.family,
                                        sock.identity.remote.addr
                                    ),
                                    sock.identity.remote.port
                                ),
                                true
                            );

                            inspect_line(
                                "local",
                                string::tformat(
                                    "[%s]:%d",
                                    fetch::convert_ip(tmem, 2, sock.identity.local.addr),
                                    sock.identity.local.port
                                ),
                                false
                            );

                            String state_display = string::tformat("%s", sock.state);
                            ClayColor state_color = (sock.state
                                == SocketState.ESTABLISHED) ? COLOR_GREEN : COLOR_WARN;

                            clay::@ui_with_id(
                                clay::@id("inspect-state"),
                                {
                                    .layout = {
                                        .layout_direction = clay::ClayLayoutDirection
                                            .LEFT_TO_RIGHT,
                                        .sizing = {
                                            .width = clay::sizing_grow(),
                                            .height = clay::sizing_fixed(20)
                                        },
                                        .padding = {
                                            .left = 0,
                                            .right = 0,
                                            .top = 0,
                                            .bottom = 0
                                        },
                                        .child_gap = 6,
                                    },
                                }
                            ) {
                                clay::@text(clay::@string("state"), text_cfg(COLOR_DIM, 20));
                                clay::@text(clay::@string("["), text_cfg(COLOR_DIM, 20));
                                clay::@text(
                                    clay::@string(state_display),
                                    text_cfg(state_color, 20)
                                );
                                clay::@text(clay::@string("]"), text_cfg(COLOR_DIM, 20));
                            };

                            if (stats) {
                                inspect_line(
                                    "sent",
                                    string::tformat("%d KB", stats.sent / 1024),
                                    false
                                );
                                inspect_line(
                                    "recv",
                                    string::tformat("%d KB", stats.received / 1024),
                                    false
                                );
                            }
                        };
                    };
                } else {
                    clay::@ui_with_id(
                        clay::@id("inspect-empty"),
                        {
                            .layout = {
                                .layout_direction = clay::ClayLayoutDirection.TOP_TO_BOTTOM,
                                .sizing = {
                                    .width = clay::sizing_grow(),
                                    .height = clay::sizing_grow()
                                },
                                .padding = { .top = 8, .bottom = 0 },
                            },
                        }
                    ) {
                        clay::@text(clay::@string("no sockets"), text_cfg(COLOR_DIM, 20));
                    };
                }
            };
        };

        clay::@ui_with_id(
            clay::@id("footer"),
            {
                .layout = {
                    .layout_direction = clay::ClayLayoutDirection.LEFT_TO_RIGHT,
                    .sizing = { .width = clay::sizing_grow(), .height = clay::sizing_fixed(24) },
                    .padding = { .left = 0, .right = 0, .top = 12, .bottom = 0 },
                    .child_gap = 16,
                    .child_alignment = {
                        .x = clay::ClayLayoutAlignmentX.CENTER,
                        .y = clay::ClayLayoutAlignmentY.CENTER
                    },
                },
                .border = { .color = COLOR_BORDER, .width = { .top = 1 }, },
            }
        ) {
            footer_key("[up / down / j / k]", "navigate", 0);
            clay::@text(clay::@string(" "), text_cfg(COLOR_DIM, 18));
            footer_key("[tab]", "switch focus", 1);
            clay::@text(clay::@string(" "), text_cfg(COLOR_DIM, 18));
            footer_key("[gg]", "top", 2);
            clay::@text(clay::@string(" "), text_cfg(COLOR_DIM, 18));
            footer_key("[Shift + G]", "end", 3);
            clay::@text(clay::@string(" "), text_cfg(COLOR_DIM, 18));
            footer_key("[q]", "quit", 4);
        };
    };
}

fn clay::ClayDimensions measure_text(
    clay::ClayStringSlice text,
    clay::ClayTextElementConfig* config,
    void* user_data
) => @pool() {
    String s        = (String)text.chars[:text.length];
    ZString z       = s.zstr_tcopy();
    rl::RLFont font = g_font;
    rl::RLVector2 size = rl::measure_text_ex(
        font,
        z,
        (float)config.font_size,
        (float)config.letter_spacing
    );
    return { .width = size.x, .height = size.y };
}

fn rl::RLColor to_rl_color(clay::ClayColor c) => { (char)c.r, (char)c.g, (char)c.b, (char)c.a };

fn void clay_raylib_render(clay::ClayRenderCommandArray* commands) => @pool() {
    for (int i = 0; i < commands.length; i++) {
        clay::ClayRenderCommand* cmd = clay::render_command_array_get(commands, i);
        clay::ClayBoundingBox bb     = cmd.bounding_box;
        rl::RLRectangle rect         = { bb.x, bb.y, bb.width, bb.height };

        switch (cmd.command_type) {
            case clay::ClayRenderCommandType.RECTANGLE:
                clay::ClayRectangleRenderData rd = cmd.render_data.rectangle;
                rl::RLColor color = to_rl_color(rd.background_color);
                if (rd.corner_radius.top_left > 0) {
                    float shortest = bb.width < bb.height ? bb.width : bb.height;
                    float roundness = shortest > 0 ? (2.0f * rd.corner_radius.top_left)
                        / shortest : 0;
                    rl::draw_rectangle_rounded(rect, roundness, 8, color);
                } else {
                    rl::draw_rectangle_rec(rect, color);
                }
            case clay::ClayRenderCommandType.BORDER:
                clay::ClayBorderRenderData bd = cmd.render_data.border;
                rl::RLColor color = to_rl_color(bd.color);
                if (bd.width.left > 0) {
                    rl::draw_rectangle((int)bb.x, (int)bb.y, bd.width.left, (int)bb.height, color);
                }
                if (bd.width.right > 0) {
                    rl::draw_rectangle(
                        (int)(bb.x + bb.width) - bd.width.right,
                        (int)bb.y,
                        bd.width.right,
                        (int)bb.height,
                        color
                    );
                }
                if (bd.width.top > 0) {
                    rl::draw_rectangle((int)bb.x, (int)bb.y, (int)bb.width, bd.width.top, color);
                }
                if (bd.width.bottom > 0) {
                    rl::draw_rectangle(
                        (int)bb.x,
                        (int)(bb.y + bb.height) - bd.width.bottom,
                        (int)bb.width,
                        bd.width.bottom,
                        color
                    );
                }
            case clay::ClayRenderCommandType.TEXT:
                clay::ClayTextRenderData td = cmd.render_data.text;
                String s = (String)td.string_contents.chars[:td.string_contents.length];
                ZString z = s.zstr_tcopy();
                rl::RLFont font = g_font;
                rl::draw_text_ex(
                    font,
                    z,
                    { bb.x, bb.y },
                    (float)td.font_size,
                    (float)td.letter_spacing,
                    to_rl_color(td.text_color)
                );
            case clay::ClayRenderCommandType.SCISSOR_START:
                rl::begin_scissor_mode((int)bb.x, (int)bb.y, (int)bb.width, (int)bb.height);
            case clay::ClayRenderCommandType.SCISSOR_END:
                rl::end_scissor_mode();
            case clay::ClayRenderCommandType.IMAGE:
            case clay::ClayRenderCommandType.CUSTOM:
            case clay::ClayRenderCommandType.OVERLAY_COLOR_START:
            case clay::ClayRenderCommandType.OVERLAY_COLOR_END:
            case clay::ClayRenderCommandType.NONE:
                nextcase default;
            default:
                break;
        }
    }
}

fn void on_error(clay::ClayErrorData error_data) {
    io::eprintfn(
        "clay error: %s",
        (String)error_data.error_text.chars[:error_data.error_text.length]
    );
}

fn void init_ui(NetworkChannel* channel) {
    @pool_init(&channel.libc, 256) {
        rl::init_window(1280, 720, "fwmp");
        ZString font_path = string::tformat_zstr("%s/FiraCode-Regular.ttf", get_path());
        g_font = rl::load_font(font_path);

        g_font.texture.set_filter(rl::RLTextureFilter.BILINEAR);
        rl::set_target_fps(60);

        uint mem_size   = clay::min_memory_size();
        char[] clay_buf = mem::new_array(char, mem_size);
        defer mem::free(clay_buf);
        clay::ClayArena arena = clay::create_arena_with_capacity_and_memory(mem_size, clay_buf.ptr);

        clay::ClayContext* ctx = clay::initialize(
            arena,
            { .width = (float)rl::get_screen_width(), .height = (float)rl::get_screen_height() },
            { .handler = &on_error }
        );
        clay::set_current_context(ctx);
        clay::set_measure_text_function(&measure_text, null);

        bool quit = false;
        while (!rl::window_should_close() && !quit) {
            @pool() {
                if (rl::is_key_pressed(rl::RLKeyboardKey.Q)) {
                    quit = true;
                    channel.quit = true;
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.TAB)) {
                    if (g_focus == "apps") {
                        g_focus = "sockets";
                        if (g_sock_count > 0) g_sock_idx = 0;
                    } else {
                        g_focus = "apps";
                        if (g_app_count > 0) g_app_idx = 0;
                    }
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.DOWN)) {
                    if (g_focus == "apps") {
                        if (g_app_count > 0) {
                            int new_idx = math::min(g_app_idx + 1, g_app_count - 1);
                            g_app_idx = new_idx;
                            g_selected_app_id = g_app_ids[new_idx];
                            g_sock_idx = 0;
                        }
                    } else {
                        if (g_sock_count > 0) {
                            g_sock_idx = math::min(g_sock_idx + 1, g_sock_count - 1);
                        }
                    }
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.UP)) {
                    if (g_focus == "apps") {
                        if (g_app_count > 0) {
                            int new_idx = math::max(g_app_idx - 1, 0);
                            g_app_idx = new_idx;
                            g_selected_app_id = g_app_ids[new_idx];
                            g_sock_idx = 0;
                        }
                    } else {
                        if (g_sock_count > 0) {
                            g_sock_idx = math::max(g_sock_idx - 1, 0);
                        }
                    }
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.J)) {
                    if (g_focus == "apps") {
                        if (g_app_count > 0) {
                            int new_idx = math::min(g_app_idx + 1, g_app_count - 1);
                            g_app_idx = new_idx;
                            g_selected_app_id = g_app_ids[new_idx];
                            g_sock_idx = 0;
                        }
                    } else {
                        if (g_sock_count > 0) {
                            g_sock_idx = math::min(g_sock_idx + 1, g_sock_count - 1);
                        }
                    }
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.K)) {
                    if (g_focus == "apps") {
                        if (g_app_count > 0) {
                            int new_idx = math::max(g_app_idx - 1, 0);
                            g_app_idx = new_idx;
                            g_selected_app_id = g_app_ids[new_idx];
                            g_sock_idx = 0;
                        }
                    } else {
                        if (g_sock_count > 0) {
                            g_sock_idx = math::max(g_sock_idx - 1, 0);
                        }
                    }
                }

                if (rl::is_key_pressed(rl::RLKeyboardKey.ENTER)) {
                    if (g_focus == "apps") {
                        g_focus = "sockets";
                        if (g_sock_count > 0) g_sock_idx = 0;
                    }
                }

                float g_pressed_at                = 0.0f;
                const float GG_TIMEOUT            = 0.4f;
                bool g_pressed_once               = false;
                static float g_pressed_at_static  = 0.0f;
                static bool g_pressed_once_static = false;

                bool g_scroll_to_top    = false;
                bool g_scroll_to_bottom = false;

                if (rl::is_key_pressed(rl::RLKeyboardKey.G)) {
                    bool shift = rl::is_key_down(rl::RLKeyboardKey.LEFT_SHIFT)
                        || rl::is_key_down(rl::RLKeyboardKey.RIGHT_SHIFT);
                    if (shift) {
                        if (g_sock_count > 0) {
                            g_sock_idx = g_sock_count - 1;
                            g_focus = "sockets";
                        }
                        g_pressed_once_static = false;
                        g_scroll_to_bottom = true;
                    } else if (g_pressed_once_static
                        && (rl::get_time() - g_pressed_at_static) < GG_TIMEOUT) {
                        g_sock_idx = 0;
                        g_focus = "sockets";
                        g_scroll_to_top = true;
                        g_pressed_once_static = false;
                    } else {
                        g_pressed_once_static = true;
                        g_pressed_at_static = (float)rl::get_time();
                    }
                }

                rl::RLVector2 mouse_pos = rl::get_mouse_position();
                bool mouse_down         = rl::is_mouse_button_down(rl::RLMouseButton.LEFT);
                bool mouse_clicked      = rl::is_mouse_button_pressed(rl::RLMouseButton.LEFT);
                clay::set_pointer_state({ mouse_pos.x, mouse_pos.y }, mouse_down);

                float wheel_y        = rl::get_mouse_wheel_move();
                float scroll_delta_y = wheel_y;

                if (g_scroll_to_top) {
                    scroll_delta_y = 100000;
                    g_scroll_to_top = false;
                }
                if (g_scroll_to_bottom) {
                    scroll_delta_y = -100000;
                    g_scroll_to_bottom = false;
                }

                clay::update_scroll_containers(false, { 0, scroll_delta_y }, rl::get_frame_time());

                if (wheel_y != 0) {
                    if (g_focus == "apps") {
                        if (g_app_count > 0) {
                            int new_idx = math::clamp(g_app_idx - (int)wheel_y, 0, g_app_count - 1);
                            g_app_idx = new_idx;
                            g_selected_app_id = g_app_ids[new_idx];
                            g_sock_idx = 0;
                        }
                    } else {
                        if (g_sock_count > 0) {
                            g_sock_idx = math::clamp(
                                g_sock_idx - (int)wheel_y,
                                0,
                                g_sock_count - 1
                            );
                        }
                    }
                }

                clay::set_layout_dimensions(
                    {
                        .width = (float)rl::get_screen_width(),
                        .height = (float)rl::get_screen_height(),
                    }
                );

                clay::begin_layout();
                layout(channel, mouse_clicked);

                clay::ClayRenderCommandArray cmds = clay::end_layout(rl::get_frame_time());

                rl::begin_drawing();
                rl::clear_background(rl::BLACK);
                clay_raylib_render(&cmds);
                rl::end_drawing();
            };
        }

        rl::unload_font(g_font);
        rl::close_window();
    };
}

fn NanoDuration set_retention(long retention_secs = 100) {
    Duration d = time::sec(retention_secs);
    return d.to_nano();
}

fn NanoDuration set_fetch_interval(long tick = 100) {
    Duration d = time::ms(tick);
    return d.to_nano();
}

fn ZString get_path() {
    char* data = libc::getenv("FWMP_DATA");
    if (data == null) return "./resources";
    return (ZString)data;
}

fn void main(String[] args) {
    Thread t_1, t_2, t_3;

    NetworkChannel nc = { };
    LibcAllocator libc;

    nc.libc = libc;
    nc.channel = channel::create_buffered(&libc, 1024)!!;
    nc.snapshot_channel = channel::create_buffered(&libc, 1024)!!;

    defer nc.channel.destroy();
    defer nc.snapshot_channel.destroy();

    ZString path   = string::tformat_zstr("%s/fwmp.bpf.o", get_path());
    BpfObject* obj = libbpf::bpf_object__open(path);

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
        io::printfn("INFO: attached %s", section);
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

    HashMap{Application, ulong} app_map;
    app_map.init(&libc, 1024);
    defer app_map.free();

    HashMap{ulong, Socket} sock_map;
    sock_map.init(&libc, 1024);
    defer sock_map.free();

    HashMap{uint, ProcessInfo} process_map;
    process_map.init(&libc, 1024);
    defer process_map.free();


    nc.map_fd = map_fd;
    nc.ring_buf_ctx = &ring_buf_ctx;
    nc.rb = rb;
    nc.network_stats.sent = sock_bytes_sent;
    nc.network_stats.recv = sock_bytes_recv;
    nc.fetch_interval = set_fetch_interval();
    nc.app_map = app_map;
    nc.sock_map = sock_map;
    nc.next_app_id = 0;
    nc.retention = set_retention();
    nc.process_map = process_map;

    t_3.create((ThreadFn)&init_ui, &nc)!!;
    t_1.create((ThreadFn)&fetch::fetch_data_from_ebpf, &nc)!!;
    t_2.create((ThreadFn)&fetch::snapshot_loop, &nc)!!;

    t_1.join()!!;
    t_2.join()!!;
    t_3.join()!!;

    foreach (link : links) {
        libbpf::bpf_link__destroy(link);
    }

    libbpf::ring_buffer__free(rb);
    libbpf::bpf_object__close(obj);

    nc.channel.close();
    nc.snapshot_channel.close();
}
