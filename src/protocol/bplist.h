#pragma once
// Minimal Apple binary plist (bplist00) writer/reader — only what the 0x1c media offer/answer needs.
// The writer reproduces Python plistlib.dumps(fmt=FMT_BINARY, sort_keys=True) byte-for-byte for a
// flat dict of {str: bytes|int|str}.
#include "common/bytes.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace scshr::bplist {

struct Value;
using Dict = std::map<std::string, Value>;   // std::map iterates sorted = plistlib sort_keys
using Array = std::vector<Value>;
struct Value {
    std::variant<std::monostate, bool, int64_t, double, std::string, Bytes, std::shared_ptr<Dict>, std::shared_ptr<Array>> v;
    Value() = default;
    Value(int64_t i) : v(i) {}
    Value(int i) : v(int64_t(i)) {}
    Value(std::string s) : v(std::move(s)) {}
    Value(const char* s) : v(std::string(s)) {}
    Value(Bytes b) : v(std::move(b)) {}
    Value(Dict d) : v(std::make_shared<Dict>(std::move(d))) {}
    const Dict* dict() const { auto p = std::get_if<std::shared_ptr<Dict>>(&v); return p ? p->get() : nullptr; }
    const Bytes* data() const { return std::get_if<Bytes>(&v); }
    const std::string* str() const { return std::get_if<std::string>(&v); }
    const int64_t* integer() const { return std::get_if<int64_t>(&v); }
};

Bytes dump(const Dict& root);
// Parse a complete bplist buffer. nullopt on any structural error (never throws; input is untrusted).
std::optional<Value> load(ByteView data);

}  // namespace scshr::bplist
