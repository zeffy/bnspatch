// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "../fwd.h"
#include "header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS; // these should be considered "intrinsics"

namespace muu
{
	inline namespace literals
	{
		/// \brief	Creates a size_t.
		/// \detail \cpp
		/// const size_t val = 42_sz;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		size_t operator"" _sz(unsigned long long n) noexcept
		{
			return static_cast<size_t>(n);
		}

		/// \brief	Creates a size_t for a given number of bytes.
		/// \detail \cpp
		/// const size_t val = 42_b; // 42
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		size_t operator"" _b(unsigned long long b) noexcept
		{
			return static_cast<size_t>(b);
		}

		/// \brief	Creates a size_t for a given number of kilobytes.
		/// \detail \cpp
		/// const size_t val = 42_kb; // 42 * 1024
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		size_t operator"" _kb(unsigned long long kb) noexcept
		{
			return static_cast<size_t>(kb * 1024ull);
		}

		/// \brief	Creates a size_t for a given number of megabytes.
		/// \detail \cpp
		/// const size_t val = 42_mb; // 42 * 1024 * 1024
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		size_t operator"" _mb(unsigned long long mb) noexcept
		{
			return static_cast<size_t>(mb * 1024ull * 1024ull);
		}

		/// \brief	Creates a size_t for a given number of gigabytes.
		/// \detail \cpp
		/// const size_t val = 42_gb; // 42 * 1024 * 1024 * 1024
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		size_t operator"" _gb(unsigned long long gb) noexcept
		{
			return static_cast<size_t>(gb * 1024ull * 1024ull * 1024ull);
		}

		/// \brief	Creates a uint8_t.
		/// \detail \cpp
		/// const uint8_t val = 42_u8;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		uint8_t operator"" _u8(unsigned long long n) noexcept
		{
			return static_cast<uint8_t>(n);
		}

		/// \brief	Creates a uint16_t.
		/// \detail \cpp
		/// const uint16_t val = 42_u16;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		uint16_t operator"" _u16(unsigned long long n) noexcept
		{
			return static_cast<uint16_t>(n);
		}

		/// \brief	Creates a uint32_t.
		/// \detail \cpp
		/// const uint32_t val = 42_u32;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		uint32_t operator"" _u32(unsigned long long n) noexcept
		{
			return static_cast<uint32_t>(n);
		}

		/// \brief	Creates a uint64_t.
		/// \detail \cpp
		/// const uint64_t val = 42_u64;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		uint64_t operator"" _u64(unsigned long long n) noexcept
		{
			return static_cast<uint64_t>(n);
		}

		/// \brief	Creates an int8_t.
		/// \detail \cpp
		/// const int8_t val = 42_i8;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		int8_t operator"" _i8(unsigned long long n) noexcept
		{
			return static_cast<int8_t>(n);
		}

		/// \brief	Creates an int16_t.
		/// \detail \cpp
		/// const int16_t val = 42_i16;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		int16_t operator"" _i16(unsigned long long n) noexcept
		{
			return static_cast<int16_t>(n);
		}

		/// \brief	Creates an int32_t.
		/// \detail \cpp
		/// const int32_t val = 42_i32;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		int32_t operator"" _i32(unsigned long long n) noexcept
		{
			return static_cast<int32_t>(n);
		}

		/// \brief	Creates an int64_t.
		/// \detail \cpp
		/// const int64_t val = 42_i64;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		int64_t operator"" _i64(unsigned long long n) noexcept
		{
			return static_cast<int64_t>(n);
		}

#if MUU_HAS_INT128

		/// \brief	Creates an int128_t.
		/// \detail \cpp
		/// const int128_t val = 42_i128;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		int128_t operator"" _i128(unsigned long long n) noexcept
		{
			return static_cast<int128_t>(n);
		}

		/// \brief	Creates a uint128_t.
		/// \detail \cpp
		/// const uint128_t val = 42_u128;
		/// \ecpp
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_CONSTEVAL
		uint128_t operator"" _u128(unsigned long long n) noexcept
		{
			return static_cast<uint128_t>(n);
		}

#endif
	}
}

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "header_end.h"
