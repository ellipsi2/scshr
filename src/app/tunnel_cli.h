#pragma once
// `scshr init` / `scshr status` / `scshr tunnel …` and the fail-closed session preflight.
#include <string>

namespace scshr::app {

// Returns true if argv[1] named a tunnel subcommand; `exit_code` then holds the process result.
bool run_tunnel_command(int argc, char** argv, int& exit_code);

// Resolves the address a production session must use.
//   direct == true  → `host` is returned unchanged (development / replay only)
//   direct == false → the peer's tunnel address, after verifying the tunnel is installed,
//                     running, correctly routed and bound to the expected peer identity.
// Throws std::runtime_error (fail closed) rather than falling back to a public address.
std::string resolve_session_host(const std::string& requested_host, bool direct);

// Installs or reconciles the Windows half of the tunnel from a macOS SCST1 code (identity, conf,
// service, route audit with rollback) and returns the SCCL1 code for the Mac. Requires an elevated
// process; throws std::runtime_error with a redacted message on failure. `report`, if given,
// receives the same human-readable summary `scshr init` prints.
std::string install_windows_tunnel(const std::string& server_code, std::string* report);

}  // namespace scshr::app
