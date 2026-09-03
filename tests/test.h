#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace scshr::test {
struct Case { const char* name; std::function<void()> fn; };
std::vector<Case>& cases();
extern int failures;
struct Reg { Reg(const char* n, std::function<void()> f) { cases().push_back({n, std::move(f)}); } };
}

#define TEST(name) static void test_##name(); static ::scshr::test::Reg reg_##name(#name, test_##name); static void test_##name()
#define CHECK(cond) do { if (!(cond)) { std::printf("  CHECK failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); ++::scshr::test::failures; } } while (0)
#define CHECK_EQ(a, b) do { auto _a = (a); auto _b = (b); if (!(_a == _b)) { std::printf("  CHECK_EQ failed: %s == %s (%s:%d)\n", #a, #b, __FILE__, __LINE__); ++::scshr::test::failures; } } while (0)
