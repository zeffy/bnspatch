// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define RPC_USE_NATIVE_WCHAR
#include <phnt_windows.h>
#include <phnt.h>
#pragma comment( lib, "ntdll.lib" )
#pragma comment( lib, "version.lib" )
#include <bcrypt.h>
#pragma comment( lib, "bcrypt.lib" )
#include <Winsock2.h>
#include <ShlObj.h>
#include <KnownFolders.h>
#include <Shlwapi.h>
#pragma comment( lib, "Shlwapi.lib" )
#include <WS2tcpip.h>
#pragma comment( lib, "Ws2_32.lib" )

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <codecvt>

#include <PathCch.h>
#include <strsafe.h>

#include <safeint.hpp>
using uchar = unsigned char;
using ushort = unsigned short;
using uint = unsigned int;
using ulong = unsigned long;
using ullong = unsigned long long;
using llong = long long;

using safe_char = SafeInt<char>;
using safe_uchar = SafeInt<uchar>;
using safe_short = SafeInt<short>;
using safe_ushort = SafeInt<ushort>;
using safe_int = SafeInt<int>;
using safe_uint = SafeInt<uint>;
using safe_long = SafeInt<long>;
using safe_ulong = SafeInt<ulong>;
using safe_llong = SafeInt<llong>;
using safe_ullong = SafeInt<ullong>;
using safe_size_t = SafeInt<size_t>;
using safe_ptrdiff_t = SafeInt<ptrdiff_t>;
using safe_float = SafeInt<float>;
using safe_double = SafeInt<double>;

#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdint>

#include <algorithm>
#include <array>
#include <bit>
#include <bitset>
#include <chrono>
#include <execution>
#include <format>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <queue>
#include <random>
#include <ranges>
#include <set>
#include <span>
#include <string_view>
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef __cpp_lib_string_udls
using namespace std::chrono_literals;
using namespace std::string_view_literals;
using namespace std::string_literals;
#endif

#include <ppl.h>
#include <concurrent_priority_queue.h>
#include <concurrent_queue.h>
#include <concurrent_unordered_map.h>
#include <concurrent_unordered_set.h>
#include <concurrent_vector.h>

#ifndef RESULT_DIAGNOSTICS_LEVEL
#define RESULT_DIAGNOSTICS_LEVEL 0
#endif

#include <pugixml.hpp>

#include <muu/hashing.h>

constexpr auto operator"" _fnv1a(const char *s, size_t len)
{
  return muu::fnv1a{}({s, len}).value();
}
constexpr auto operator"" _fnv1a(const wchar_t *s, size_t len)
{
  return muu::fnv1a{}({s, len}).value();
}

#if defined(__cpp_char8_t)
constexpr auto operator"" _fnv1a(const char8_t *s, size_t len)
{
  return muu::fnv1a{}({s, len}).value();
}
#endif
#if defined(__cpp_unicode_characters)
constexpr auto operator"" _fnv1a(const char16_t *s, size_t len)
{
  return muu::fnv1a{}({s, len}).value();
}

constexpr auto operator"" _fnv1a(const char32_t *s, size_t len)
{
  return muu::fnv1a{}({s, len}).value();
}
#endif

#include <ntamd64.hpp>
#include <ntmm.hpp>
#include <ntrtl.hpp>
#include <detours.hpp>

#include <wil/stl.h>
#include <wil/win32_helpers.h>
#include <wil/resource.h>
#include <wil/result.h>

#endif //PCH_H
