// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "../fwd.h"
#include "header_start.h"
MUU_PRAGMA_MSVC(warning(disable : 4296)) // condition always true/false

/// \cond
namespace muu::impl
{
	MUU_DISABLE_WARNINGS; // non-determinisitic build

	inline constexpr auto build_date_str		= __DATE__;
	inline constexpr auto build_date_month_hash = build_date_str[0] + build_date_str[1] + build_date_str[2];
	inline constexpr auto build_time_str		= __TIME__;

	MUU_ENABLE_WARNINGS;
}
/// \endcond

namespace muu::build
{
	// clang-format off

	/// \brief The current C++ language version (17, 20...)
	inline constexpr uint32_t cpp_version = MUU_CPP;
	static_assert(
		cpp_version == 17u
		|| cpp_version == 20u
		|| cpp_version == 23u //??
		|| cpp_version == 26u //??
	);

	/// \brief The current year.
	inline constexpr uint32_t year = static_cast<uint32_t>(
		(impl::build_date_str[7] - '0') * 1000
		+ (impl::build_date_str[8] - '0') * 100
		+ (impl::build_date_str[9] - '0') * 10
		+ (impl::build_date_str[10] - '0')
	);
	static_assert(year >= 2021u);

	/// \brief The current month of the year (1-12).
	inline constexpr uint32_t month = 
		impl::build_date_month_hash == 281 ? 1u : (
		impl::build_date_month_hash == 269 ? 2u : (
		impl::build_date_month_hash == 288 ? 3u : (
		impl::build_date_month_hash == 291 ? 4u : (
		impl::build_date_month_hash == 295 ? 5u : (
		impl::build_date_month_hash == 301 ? 6u : (
		impl::build_date_month_hash == 299 ? 7u : (
		impl::build_date_month_hash == 285 ? 8u : (
		impl::build_date_month_hash == 296 ? 9u : (
		impl::build_date_month_hash == 294 ? 10u : (
		impl::build_date_month_hash == 307 ? 11u : (
		impl::build_date_month_hash == 268 ? 12u : 0
	)))))))))));
	static_assert(month >= 1 && month <= 12);

	/// \brief The current day of the month (1-31).
	inline constexpr uint32_t day = static_cast<uint32_t>(
		(impl::build_date_str[4] == ' ' ? 0 : impl::build_date_str[4] - '0') * 10
		+ (impl::build_date_str[5] - '0')
	);
	static_assert(day >= 1u && day <= 31u);

	/// \brief The current hour of the day (0-23).
	inline constexpr uint32_t hour = static_cast<uint32_t>(
		(impl::build_time_str[0] == ' ' ? 0 : impl::build_time_str[0] - '0') * 10
		+ (impl::build_time_str[1] - '0')
	);
	static_assert(hour <= 23u);

	/// \brief The current minute (0-59).
	inline constexpr uint32_t minute = static_cast<uint32_t>(
		(impl::build_time_str[3] == ' ' ? 0 : impl::build_time_str[3] - '0') * 10
		+ (impl::build_time_str[4] - '0')
	);
	static_assert(minute <= 59u);

	/// \brief The current second (0-59).
	inline constexpr uint32_t second = static_cast<uint32_t>(
		(impl::build_time_str[6] == ' ' ? 0 : impl::build_time_str[6] - '0') * 10
		+ (impl::build_time_str[7] - '0')
	);
	static_assert(second <= 60u); // 60 b/c leap seconds

	/// \brief	The bitness of the current architecture.
	inline constexpr size_t bitness = MUU_ARCH_BITNESS;

	/// \brief The number of bits in a byte (aka CHAR_BIT).
	inline constexpr size_t bits_per_byte = CHAR_BIT;

	/// \brief The number of bytes required to store a pointer.
	inline constexpr size_t pointer_size = sizeof(void*);

	/// \brief True if exceptions are enabled.
	inline constexpr bool has_exceptions = !!MUU_HAS_EXCEPTIONS;

	/// \brief True if run-time type identification (RTTI) is enabled.
	inline constexpr bool has_rtti = !!MUU_HAS_RTTI;

	/// \brief True if the target environment is little-endian.
	inline constexpr bool is_little_endian = !!MUU_LITTLE_ENDIAN;

	/// \brief True if the target environment is big-endian.
	inline constexpr bool is_big_endian = !!MUU_BIG_ENDIAN;
	
	static_assert(pointer_size * bits_per_byte == bitness);
	static_assert(is_little_endian != is_big_endian);

	// clang-format on
}

#include "header_end.h"
