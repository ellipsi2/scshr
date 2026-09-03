#pragma once
// RFB authentication: Apple SRP-RFC5054-4096-SHA512-PBKDF2 (type 33 "RSA1" envelope) and the
// legacy non-SRP RSA1+AES path. Both return the 16-byte record-layer wrap key.
#include "common/bytes.h"
#include "net/tcp.h"

#include <array>
#include <stdexcept>
#include <string>

namespace scshr::auth {

struct AuthError : std::runtime_error { using std::runtime_error::runtime_error; };

std::array<uint8_t, 16> do_srp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password);
std::array<uint8_t, 16> do_nonsrp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password);

// Exposed for unit tests / vectors: the pure SRP math given challenge parameters and a fixed `a`.
struct SrpChallenge { Bytes N, salt, B, cap; uint32_t g = 5; uint64_t iterations = 0; };
struct SrpProof { Bytes A, M1, K; };
SrpChallenge parse_srp_challenge(ByteView s2c1);
Bytes derive_x(ByteView salt, uint64_t iterations, const std::string& password);  // 64-byte SHA-512 (pre-mod)
SrpProof solve_srp(const SrpChallenge& ch, const std::string& password, ByteView a_override = {});

}  // namespace scshr::auth
