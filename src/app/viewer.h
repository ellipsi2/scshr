#pragma once
// The viewer (window + renderer + session + input + audio), callable from the CLI and from the GUI
// launcher. Runs its render loop on the calling thread and returns when the window is closed, the
// connection drops, or the session cannot be established.
#include <optional>
#include <string>

namespace scshr::app {

struct ViewerOptions {
    std::string host, user, password, log_file, advertise = "auto", hidpi = "auto", codec = "auto", decoder = "auto", present = "vsync", record, display = "all";
    std::string title_label;   // shown in the window title ("" → host)
    uint16_t port = 5900;
    bool password_stdin = false, srp = true, hdr = false, curtain = true, share_console = false, alt_session = false, audio = true, verbose = false, quiet = false;
    std::optional<bool> dynamic;
    bool clipboard = true, grab = true, ltrp = true, legacy_cursor = false;
    int auto_quit = 0, adapter = -1, tiles = 0, stats_interval = 2;
    double drop_pct = 0;
    bool list_adapters = false, headless = false, direct = false;
    std::string replay_key;    // hex 46-byte video key: replay mode (media from scshr_sender, no TCP)
};

enum class ViewerExit { Closed, ConnectFailed, ConnectionLost, Error };

struct ViewerResult {
    ViewerExit exit = ViewerExit::Closed;
    std::string error;         // plain text for the user when exit != Closed
    int exit_code = 0;         // CLI process exit code
};

void usage();
// CLI parsing (argv[1..]); false + message on stderr for bad arguments. Does not read the password.
bool parse_viewer_args(int argc, char** argv, ViewerOptions& o);
// Resolves the host through the tunnel preflight (unless direct/replay) and runs the viewer.
// `o.password` must already be filled (GUI) unless o.password_stdin / console prompting applies.
ViewerResult run_viewer(ViewerOptions& o);

}  // namespace scshr::app
