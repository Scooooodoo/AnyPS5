#include "prx/libSceIcu/libSceIcu.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "ICU termination check failed at line %u\n", location.line());
    std::abort();
}

enum Outcome { Fits, Exact, Overflow, Ignored };

struct Case {
    std::int32_t capacity;
    std::int32_t length;
    Outcome outcome;
};

struct StatusCase {
    std::int32_t initial;
    std::array<std::int32_t, 4> expected;
};

constexpr auto Minimum = std::numeric_limits<std::int32_t>::min();
constexpr auto Maximum = std::numeric_limits<std::int32_t>::max();
constexpr StatusCase StatusCases[]{
    {0, {0, -124, 15, 0}},
    {-124, {0, -124, 15, -124}},
    {-127, {-127, -124, 15, -127}},
    {-128, {-128, -124, 15, -128}},
    {1, {1, 1, 1, 1}},
    {15, {15, 15, 15, 15}},
    {Minimum, {Minimum, -124, 15, Minimum}},
    {Maximum, {Maximum, Maximum, Maximum, Maximum}}
};

std::vector<Case> Cases() {
    std::vector<Case> cases{
        {0, 0, Exact}, {0, 1, Overflow}, {1, 0, Fits}, {1, 1, Exact}, {1, 2, Overflow},
        {16, 15, Fits}, {16, 16, Exact}, {16, 17, Overflow},
        {-1, 0, Overflow}, {Minimum, 0, Overflow}, {-1, -1, Ignored}, {0, -1, Ignored},
        {16, Minimum, Ignored}, {Minimum, -1, Ignored},
        {Maximum, Maximum, Exact}, {Maximum - 1, Maximum, Overflow}, {-1, Maximum, Overflow}
    };
    for (std::int32_t length = 0; length < 16; ++length) {
        cases.push_back({length + 1, length, Fits});
        cases.push_back({length, length, Exact});
        cases.push_back({length, length + 1, Overflow});
    }
    return cases;
}

template<typename TCall>
void Check(TCall call, const Case& row, const StatusCase& status, bool hasDestination, bool hasStatus) {
    std::array<char, 20> output;
    for (std::size_t index = 0; index < output.size(); ++index)
        output[index] = static_cast<char>(0xa540 + index);
    output[3] = 0;
    auto expected = output;
    const bool active = hasStatus && status.initial <= 0;
    const bool writes = active && row.outcome == Fits;
    const bool rejects = writes && !hasDestination;
    if (writes && hasDestination) expected[1 + row.length] = 0;
    std::array<std::int32_t, 3> errors{0x13579bdf, status.initial, 0x2468ace0};
    auto expectedErrors = errors;
    if (active && !rejects) expectedErrors[1] = status.expected[row.outcome];
    bool caught = false;
    try {
        Require(call(hasDestination ? output.data() + 1 : nullptr, row.capacity, row.length,
            hasStatus ? &errors[1] : nullptr) == row.length);
    } catch (const std::invalid_argument&) {
        caught = true;
    }
    Require(caught == rejects);
    Require(output == expected && errors == expectedErrors);
}

template<typename TCall>
void Recovery(TCall call) {
    std::array<char, 5> output{u'a', u'b', u'c', 0x55, 0x66};
    std::int32_t error = 0;
    Require(call(output.data(), 3, 3, &error) == 3 && error == -124 && output[3] == 0x55);
    Require(call(output.data(), 4, 3, &error) == 3 && error == 0 && output[3] == 0);
    output[3] = 0x55;
    error = 15;
    Require(call(output.data(), 4, 3, &error) == 3 && error == 15 && output[3] == 0x55);
    error = -127;
    Require(call(output.data(), 4, 3, &error) == 3 && error == -127 && output[3] == 0);
    Require(output[0] == u'a' && output[1] == u'b' && output[2] == u'c' && output[4] == 0x66);
}

template<typename TCall>
std::size_t Run(TCall call) {
    std::size_t checks = 0;
    for (const auto& row : Cases()) {
        for (const auto& status : StatusCases) {
            for (bool hasDestination : {false, true}) {
                for (bool hasStatus : {false, true}) {
                    Check(call, row, status, hasDestination, hasStatus);
                    ++checks;
                }
            }
        }
    }
    Recovery(call);
    return checks;
}

}

int main(int argc, char** argv) {
    Require(argc == 3);
    using Chars = decltype(&u_terminateChars_nid_postfix);
#ifdef _WIN32
    const auto library = LoadLibraryExW(std::filesystem::path(argv[1]).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!library) std::fprintf(stderr, "LoadLibraryExW failed: %lu\n", GetLastError());
    Require(library != nullptr);
    const auto chars = std::bit_cast<Chars>(GetProcAddress(library, argv[2]));
#else
    const auto library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) std::fprintf(stderr, "%s\n", dlerror());
    Require(library != nullptr);
    const auto chars = reinterpret_cast<Chars>(dlsym(library, argv[2]));
#endif
    Require(chars);
    const auto checks = Run(chars);
    std::printf("ICU byte termination: %zu matrix calls and one warning/error recovery sequence passed\n", checks);
}
