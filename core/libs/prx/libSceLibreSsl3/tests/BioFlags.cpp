#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include <array>
#include <bit>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <type_traits>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

using ChangeFlags = decltype(&BIO_set_flags_nid_postfix);
static_assert(std::is_same_v<ChangeFlags, decltype(&BIO_clear_flags_nid_postfix)>);

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 BIO flags check failed at line %u\n", location.line());
    std::abort();
}

class Fixture {
public:
    explicit Fixture(std::uint32_t initial) {
        for (std::size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<unsigned char>(index * 73 + 19);
        std::memcpy(bytes.data() + FlagsOffset, &initial, sizeof(initial));
    }

    void Apply(ChangeFlags change, std::uint32_t mask, std::uint32_t expectedFlags) {
        auto expected = bytes;
        std::memcpy(expected.data() + FlagsOffset, &expectedFlags, sizeof(expectedFlags));
        change(reinterpret_cast<LibreSsl3Bio*>(bytes.data() + BioOffset), std::bit_cast<std::int32_t>(mask));
        Require(bytes == expected);
    }

private:
    static constexpr std::size_t BioOffset = 8;
    static constexpr std::size_t FlagsOffset = BioOffset + 40;
    alignas(8) std::array<unsigned char, 8 + 112 + 8> bytes;
};

void CheckMask(ChangeFlags set, ChangeFlags clear, std::uint32_t initial, std::uint32_t mask) {
    std::bitset<32> enabled(initial), disabled(initial);
    const std::bitset<32> selected(mask);
    for (std::size_t bit = 0; bit < selected.size(); ++bit) {
        if (!selected.test(bit)) continue;
        enabled.set(bit);
        disabled.reset(bit);
    }
    Fixture setFixture(initial), clearFixture(initial);
    setFixture.Apply(set, mask, static_cast<std::uint32_t>(enabled.to_ullong()));
    clearFixture.Apply(clear, mask, static_cast<std::uint32_t>(disabled.to_ullong()));
}

void CheckRetrySequence(ChangeFlags set, ChangeFlags clear) {
    Fixture fixture(0x40000000);
    fixture.Apply(set, 0x09, 0x40000009);
    fixture.Apply(set, 0x09, 0x40000009);
    fixture.Apply(clear, 0x0f, 0x40000000);
    fixture.Apply(set, 0x0a, 0x4000000a);
    fixture.Apply(clear, 0x01, 0x4000000a);
    fixture.Apply(clear, 0x0f, 0x40000000);
    fixture.Apply(set, 0x0c, 0x4000000c);
    fixture.Apply(clear, 0x0f, 0x40000000);
    fixture.Apply(set, 0x80000000, 0xc0000000);
    fixture.Apply(clear, 0x80000000, 0x40000000);
    fixture.Apply(clear, 0, 0x40000000);
    fixture.Apply(set, 0, 0x40000000);
}

void Run(ChangeFlags set, ChangeFlags clear) {
    for (std::uint32_t initial : {0u, 0xffffffffu, 0xa55aa55au, 0x80000000u, 0x7fffffffu}) {
        for (std::uint32_t mask : {0u, 0xffffffffu, 0xa55aa55au, 0x5aa55aa5u, 1u, 0x80000000u, 0x7fffffffu})
            CheckMask(set, clear, initial, mask);
    }
    for (unsigned int initialBit = 0; initialBit < 32; ++initialBit) {
        for (unsigned int maskBit = 0; maskBit < 32; ++maskBit)
            CheckMask(set, clear, std::uint32_t{1} << initialBit, std::uint32_t{1} << maskBit);
    }
    CheckRetrySequence(set, clear);
    for (auto change : {set, clear}) {
        for (int flags : {0, 1, -1, std::numeric_limits<int>::min()}) {
            bool caught = false;
            try {
                change(nullptr, flags);
            } catch (const std::invalid_argument&) {
                caught = true;
            }
            Require(caught);
        }
    }
    std::puts("LibreSSL3 BIO flags: 2130 updates, surrounding bytes, retry transitions and eight null guards passed");
}

}

int main(int argc, char** argv) {
    Require(argc == 4);
#ifdef _WIN32
    const auto library = LoadLibraryExW(std::filesystem::path(argv[1]).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!library) std::fprintf(stderr, "LoadLibraryExW failed: %lu\n", GetLastError());
    Require(library != nullptr);
    const auto set = std::bit_cast<ChangeFlags>(GetProcAddress(library, argv[2]));
    const auto clear = std::bit_cast<ChangeFlags>(GetProcAddress(library, argv[3]));
#else
    const auto library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) std::fprintf(stderr, "%s\n", dlerror());
    Require(library != nullptr);
    const auto set = reinterpret_cast<ChangeFlags>(dlsym(library, argv[2]));
    const auto clear = reinterpret_cast<ChangeFlags>(dlsym(library, argv[3]));
#endif
    Require(set && clear);
    Run(set, clear);
}
