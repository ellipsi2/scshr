// Minimal test runner (no framework dependency).
#include "tests/test.h"

#include <cstdio>

namespace scshr::test {
std::vector<Case>& cases() { static std::vector<Case> c; return c; }
int failures = 0;
}

int main(int argc, char** argv) {
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0;
    for (auto& c : scshr::test::cases()) {
        if (filter && std::string(c.name).find(filter) == std::string::npos) continue;
        const int before = scshr::test::failures;
        try { c.fn(); } catch (const std::exception& e) { std::printf("  EXCEPTION in %s: %s\n", c.name, e.what()); ++scshr::test::failures; }
        std::printf("%s %s\n", scshr::test::failures == before ? "PASS" : "FAIL", c.name);
        ++run;
    }
    std::printf("%d tests, %d failures\n", run, scshr::test::failures);
    return scshr::test::failures ? 1 : 0;
}
