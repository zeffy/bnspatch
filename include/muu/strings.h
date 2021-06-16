// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

/// \file
/// \brief Functions to simplify working with strings.

#pragma once
#include "core.h"
#include "chars.h"
#include "string_param.h"

MUU_DISABLE_WARNINGS;
#include <cstring>
#include <string>
#include <string_view>
#include <iosfwd>
MUU_ENABLE_WARNINGS;

#include "impl/header_start.h"
MUU_DISABLE_ARITHMETIC_WARNINGS;
MUU_FORCE_NDEBUG_OPTIMIZATIONS;

#ifdef __cpp_lib_constexpr_string
	#define MUU_CONSTEXPR_STRING constexpr
#else
	#define MUU_CONSTEXPR_STRING inline
#endif

namespace muu
{
	using namespace std::string_view_literals;
}

namespace muu
{
	/// \addtogroup		strings			Strings
	/// \brief			Utilities to simplify working with strings.
	/// @{

	/// \defgroup		code_units		Code units
	/// \brief			Utilities for manipulating individual code units ('characters').

#if 1 // unicode/boilerplate -------------------------------------------------------------------------------------------

	/// \cond
	namespace impl
	{
		MUU_ABI_VERSION_START(0);

		class MUU_TRIVIAL_ABI utf8_decoder final
		{
			// utf8_decoder based on this: https://bjoern.hoehrmann.de/utf-8/decoder/dfa/
			// Copyright (c) Bjoern Hoehrmann <bjoern@hoehrmann.de>

		  private:
			uint_least32_t state{};
			static constexpr uint8_t state_table[] = {
				0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
				0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
				0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
				0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
				0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	1,	1,
				1,	1,	1,	1,	1,	1,	1,	1,	1,	1,	1,	1,	1,	1,	9,	9,	9,	9,	9,	9,	9,	9,	9,	9,	9,	9,
				9,	9,	9,	9,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	7,
				7,	7,	7,	7,	7,	7,	7,	7,	7,	7,	8,	8,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,
				2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	2,	10, 3,	3,	3,	3,	3,	3,	3,	3,	3,
				3,	3,	3,	4,	3,	3,	11, 6,	6,	6,	5,	8,	8,	8,	8,	8,	8,	8,	8,	8,	8,	8,

				0,	12, 24, 36, 60, 96, 84, 12, 12, 12, 48, 72, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 0,
				12, 12, 12, 12, 12, 0,	12, 0,	12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 24, 12, 12, 12, 12, 12, 12,
				12, 12, 12, 24, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 12, 12, 24, 12, 12, 12, 12, 12, 12, 12, 12,
				12, 36, 12, 36, 12, 12, 12, 36, 12, 12, 12, 12, 12, 36, 12, 36, 12, 12, 12, 36, 12, 12, 12, 12, 12, 12,
				12, 12, 12, 12
			};
			uint_least32_t codepoint{};

		  public:
			MUU_NODISCARD
			constexpr bool error() const noexcept
			{
				return state == uint_least32_t{ 12u };
			}

			constexpr void clear_error() noexcept
			{
				MUU_ASSERT(error());
				state = uint_least32_t{};
			}

			MUU_NODISCARD
			constexpr bool has_value() const noexcept
			{
				return state == uint_least32_t{};
			}

			MUU_NODISCARD
			constexpr char32_t value() const noexcept
			{
				return static_cast<char32_t>(codepoint);
			}

			MUU_NODISCARD
			constexpr bool needs_more_input() const noexcept
			{
				return state > uint_least32_t{} && state != uint_least32_t{ 12u };
			}

			constexpr void operator()(uint8_t code_unit) noexcept
			{
				MUU_ASSERT(!error());

				const auto type = state_table[code_unit];

				codepoint = has_value()
							  ? (uint_least32_t{ 255u } >> type) & code_unit
							  : (code_unit & uint_least32_t{ 63u }) | (static_cast<uint_least32_t>(codepoint) << 6);

				state = state_table[state + uint_least32_t{ 256u } + type];
			}
			constexpr void operator()(char code_unit) noexcept
			{
				(*this)(static_cast<uint8_t>(code_unit));
			}
	#if MUU_HAS_CHAR8
			constexpr void operator()(char8_t code_unit) noexcept
			{
				(*this)(static_cast<uint8_t>(code_unit));
			}
	#endif
		};

		class MUU_TRIVIAL_ABI utf16_decoder final
		{
			enum decoder_state : unsigned
			{
				ds_initial,
				ds_expecting_low_surrogate,
				ds_has_codepoint,
				ds_error
			};
			decoder_state state{};
			uint_least32_t codepoint{};

		  public:
			MUU_NODISCARD
			constexpr bool error() const noexcept
			{
				return state == ds_error;
			}

			constexpr void clear_error() noexcept
			{
				MUU_ASSERT(error());
				state = ds_initial;
			}

			MUU_NODISCARD
			constexpr bool has_value() const noexcept
			{
				return state == ds_has_codepoint;
			}

			MUU_NODISCARD
			constexpr char32_t value() const noexcept
			{
				return static_cast<char32_t>(codepoint);
			}

			MUU_NODISCARD
			constexpr bool needs_more_input() const noexcept
			{
				return state == ds_expecting_low_surrogate;
			}

			constexpr void operator()(uint16_t code_unit) noexcept
			{
				MUU_ASSERT(!error());

				enum code_unit_classes : unsigned
				{
					basic_multilingual,
					low_surrogate  = 0b00010000u,
					high_surrogate = 0b00100000u
				};

				const auto code_unit_class = (static_cast<unsigned>(between(code_unit, 0xDC00_u16, 0xDFFF_u16)) << 4)
										   | (static_cast<unsigned>(between(code_unit, 0xD800_u16, 0xDBFF_u16)) << 5);

				switch (code_unit_class | state)
				{
					case unwrap(basic_multilingual) | ds_initial: [[fallthrough]];
					case unwrap(basic_multilingual) | ds_has_codepoint:
						codepoint = static_cast<uint_least32_t>(code_unit);
						state	  = ds_has_codepoint;
						return;

					case unwrap(high_surrogate) | ds_initial: [[fallthrough]];
					case unwrap(high_surrogate) | ds_has_codepoint:
						codepoint = static_cast<uint_least32_t>(code_unit); // will get multiplexed in the next step
						state	  = ds_has_codepoint;
						return;

					case unwrap(low_surrogate) | ds_expecting_low_surrogate:
						codepoint = ((codepoint - 0xD800u) << 10) + (static_cast<uint_least32_t>(code_unit) - 0xDC00u)
								  + 0x10000u;
						state = ds_has_codepoint;
						return;

					default: state = ds_error;
				}
			}
			constexpr void operator()(char16_t code_unit) noexcept
			{
				(*this)(static_cast<uint16_t>(code_unit));
			}
	#if MUU_WCHAR_BYTES == 2
			constexpr void operator()(wchar_t code_unit) noexcept
			{
				(*this)(static_cast<uint16_t>(code_unit));
			}
	#endif
		};

		MUU_ABI_VERSION_END;

		template <typename T>
		using utf_decoder =
			std::conditional_t<sizeof(T) == 2, utf16_decoder, std::conditional_t<sizeof(T) == 1, utf8_decoder, void>>;

		template <typename T,
				  typename Func,
				  size_t PositionalArgs = (std::is_nothrow_invocable_v<Func, T, size_t, size_t>
											   ? 2u
											   : (std::is_nothrow_invocable_v<Func, T, size_t> ? 1u : 0u))>
		struct utf_decode_func_traits
		{
			using return_type =
				decltype(std::declval<Func>()(std::declval<T>(), std::declval<size_t>(), std::declval<size_t>()));
		};

		template <typename T, typename Func>
		struct utf_decode_func_traits<T, Func, 1>
		{
			using return_type = decltype(std::declval<Func>()(std::declval<T>(), std::declval<size_t>()));
		};

		template <typename T, typename Func>
		struct utf_decode_func_traits<T, Func, 0>
		{
			using return_type = decltype(std::declval<Func>()(std::declval<T>()));
		};

		template <typename T>
		constexpr bool utf_detect_platform_endian(const T* data, const T* const end) noexcept
		{
			static_assert(sizeof(T) >= 2);
			int low{}, high{}; // number of zeroes in low/high byte
			for (auto c = data; c < end; c++)
			{
				low += static_cast<int>(byte_select<0>(*c) == uint8_t{});
				high += static_cast<int>(byte_select<sizeof(T) - 1u>(*c) == uint8_t{});
			}
			if constexpr (build::is_big_endian)
				return low > high;
			else
				return high > low;
		}

		template <typename T, typename Func>
		constexpr void utf_decode(std::basic_string_view<T> str, bool reverse, Func&& func) noexcept
		{
			if (str.empty())
				return;

			static_assert(is_code_unit<T>, "unknown code unit type");
			static_assert(
				std::is_nothrow_invocable_v<
					Func&&,
					T,
					size_t,
					size_t> || std::is_nothrow_invocable_v<Func&&, T, size_t> || std::is_nothrow_invocable_v<Func&&, T>,
				"decoder func must be nothrow-invocable with (T), (T, size_t) or (T, size_t, size_t)");

			using func_return_type = typename utf_decode_func_traits<T, Func>::return_type;
			constexpr auto stop_after_invoking =
				[](auto&& f, char32_t cp, size_t cu_start, size_t cu_count) noexcept -> bool
			{
				MUU_UNUSED(cu_start);
				MUU_UNUSED(cu_count);
				if constexpr (std::is_convertible_v<func_return_type, bool>)
				{
					if constexpr (std::is_nothrow_invocable_v<Func&&, T, size_t, size_t>)
						return !static_cast<bool>(static_cast<decltype(f)&&>(f)(cp, cu_start, cu_count));
					else if constexpr (std::is_nothrow_invocable_v<Func&&, T, size_t>)
						return !static_cast<bool>(static_cast<decltype(f)&&>(f)(cp, cu_start));
					else
						return !static_cast<bool>(static_cast<decltype(f)&&>(f)(cp));
				}
				else
				{
					if constexpr (std::is_nothrow_invocable_v<Func&&, T, size_t, size_t>)
						static_cast<decltype(f)&&>(f)(cp, cu_start, cu_count);
					else if constexpr (std::is_nothrow_invocable_v<Func&&, T, size_t>)
						static_cast<decltype(f)&&>(f)(cp, cu_start);
					else
						static_cast<decltype(f)&&>(f)(cp);
					return false;
				}
			};

			bool stop							 = false;
			size_t data_start					 = 0;
			[[maybe_unused]] bool requires_bswap = false;
			const auto get						 = [&](size_t idx) noexcept -> T
			{
				if constexpr (sizeof(T) == 1)
					return str[idx];
				else
				{
					if (requires_bswap)
						return static_cast<T>(
							byte_reverse(static_cast<unsigned_integer<sizeof(T) * CHAR_BIT>>(str[idx])));
					return str[idx];
				}
			};

			// UTF-32
			if constexpr (sizeof(T) == 4)
			{
				// endianness
				if (static_cast<uint32_t>(str[0]) == 0xFFFE0000u)
				{
					data_start	   = 1u;
					requires_bswap = true;
				}
				else if (static_cast<uint32_t>(str[0]) == 0x0000FEFFu)
					data_start = 1u;
				else
					requires_bswap = !utf_detect_platform_endian(str.data(), str.data() + min(str.length(), 16_sz));

				if (reverse)
				{
					for (size_t i = str.length(); i-- > data_start && !stop;)
						stop = stop_after_invoking(static_cast<Func&&>(func), static_cast<char32_t>(get(i)), i, 1);
				}
				else
				{
					for (size_t i = data_start, e = str.length(); i < e && !stop; i++)
						stop = stop_after_invoking(static_cast<Func&&>(func), static_cast<char32_t>(get(i)), i, 1);
				}
			}

			// UTF-8, UTF-16
			else
			{
				// endianness
				if constexpr (sizeof(T) == 1)
				{
					if (str.length() >= 3u && pack(str[0], str[1], str[2]) == 0x00EFBBBF)
						data_start = 3u;
				}
				else
				{
					if (static_cast<uint16_t>(str[0]) == 0xFFFEu)
					{
						data_start	   = 1u;
						requires_bswap = true;
					}
					else if (static_cast<uint16_t>(str[0]) == 0xFEFFu)
						data_start = 1u;
					else
						requires_bswap = !utf_detect_platform_endian(str.data(), str.data() + min(str.length(), 16_sz));
				}

				utf_decoder<T> decoder;
				if (reverse)
				{
					size_t cp_start				  = str.length();
					size_t cu_count				  = {};
					constexpr size_t max_cu_count = 4_sz / sizeof(T);
					while (cp_start-- > data_start && !stop)
					{
						cu_count++;
						if (cu_count == max_cu_count || is_code_point_boundary(get(cp_start)))
						{
							for (size_t i = cp_start, e = cp_start + cu_count; i < e; i++)
							{
								decoder(get(i));
								if (decoder.error())
									break;
							}

							if (decoder.has_value())
								stop =
									stop_after_invoking(static_cast<Func&&>(func), decoder.value(), cp_start, cu_count);
							else if (decoder.error())
							{
								decoder.clear_error();
								for (size_t i = cp_start + cu_count; i-- > cp_start && !stop;)
									stop = stop_after_invoking(static_cast<Func&&>(func),
															   static_cast<char32_t>(get(i)),
															   i,
															   1);
							}
							cu_count = {};
						}
					}
				}
				else
				{
					for (size_t i = data_start, e = str.length(), cp_start = data_start, cu_count = 0; i < e && !stop;
						 i++)
					{
						cu_count++;
						decoder(get(i));
						if (decoder.has_value())
						{
							stop = stop_after_invoking(static_cast<Func&&>(func), decoder.value(), cp_start, cu_count);
							cp_start = i + 1u;
							cu_count = {};
						}
						else if (decoder.error())
						{
							decoder.clear_error();
							for (size_t j = cp_start, je = cp_start + cu_count; j < je && !stop; j++)
								stop =
									stop_after_invoking(static_cast<Func&&>(func), static_cast<char32_t>(get(j)), j, 1);
							cp_start = i + 1u;
							cu_count = {};
						}
					}
				}
			}
		}

		template <typename T, typename Func>
		constexpr void utf_decode(std::basic_string_view<T> str, Func&& func) noexcept
		{
			utf_decode(str, false, static_cast<Func&&>(func));
		}

		MUU_ABI_VERSION_START(0);

		struct utf_find_result
		{
			size_t index;
			size_t length;

			MUU_NODISCARD
			MUU_ATTR(pure)
			explicit constexpr operator bool() const noexcept
			{
				return index != constants<size_t>::highest;
			}

			MUU_NODISCARD
			MUU_ATTR(pure)
			constexpr size_t end() const noexcept
			{
				return index + length;
			}
		};

		template <typename T, typename Func>
		constexpr utf_find_result utf_find(std::basic_string_view<T> str, bool reverse, Func&& predicate) noexcept
		{
			utf_find_result result{ constants<size_t>::highest, {} };
			if (!str.empty())
			{
				utf_decode(str,
						   reverse,
						   [&](char32_t cp, size_t starts_at, size_t goes_for) noexcept
						   {
							   if (static_cast<Func&&>(predicate)(cp))
							   {
								   result = { starts_at, goes_for };
								   return false;
							   }
							   return true;
						   });
			}
			return result;
		}

		template <typename T>
		class MUU_TRIVIAL_ABI utf8_code_point
		{
		  private:
			static_assert(sizeof(T) == 1);
			T code_units[4] = {};

		  public:
			MUU_NODISCARD_CTOR
			constexpr utf8_code_point(uint_least32_t cp) noexcept // *** assumes cp is platform-endian ***
			{
				if (cp <= 0x7Fu)
				{
					code_units[0] = static_cast<T>(cp);
				}
				else if (cp <= 0x7FFu)
				{
					code_units[0] = static_cast<T>((cp >> 6) | 0xC0u);
					code_units[1] = static_cast<T>((cp & 0x3Fu) | 0x80u);
				}
				else if (cp <= 0xFFFFu)
				{
					code_units[0] = static_cast<T>((cp >> 12) | 0xE0u);
					code_units[1] = static_cast<T>(((cp >> 6) & 0x3Fu) | 0x80u);
					code_units[2] = static_cast<T>((cp & 0x3Fu) | 0x80u);
				}
				else if (cp <= 0x10FFFFu)
				{
					code_units[0] = static_cast<T>((cp >> 18) | 0xF0u);
					code_units[1] = static_cast<T>(((cp >> 12) & 0x3Fu) | 0x80u);
					code_units[2] = static_cast<T>(((cp >> 6) & 0x3Fu) | 0x80u);
					code_units[3] = static_cast<T>((cp & 0x3Fu) | 0x80u);
				}
			}

			MUU_NODISCARD_CTOR
			constexpr utf8_code_point(char32_t cp) noexcept // *** assumes cp is platform-endian ***
				: utf8_code_point{ static_cast<uint_least32_t>(cp) }
			{}

			MUU_NODISCARD
			constexpr std::basic_string_view<T> view() const noexcept
			{
				return code_units[3] ? std::basic_string_view<T>{ code_units, 4_sz }
									 : std::basic_string_view<T>{ code_units };
			}

			MUU_NODISCARD
			constexpr operator std::basic_string_view<T>() const noexcept
			{
				return view();
			}
		};

		template <typename T>
		class MUU_TRIVIAL_ABI utf16_code_point
		{
		  private:
			static_assert(sizeof(T) == 2);
			T code_units[2] = {};

		  public:
			MUU_NODISCARD_CTOR
			constexpr utf16_code_point(uint_least32_t cp) noexcept // *** assumes cp is platform-endian ***
			{
				if (cp < 0x10000u)
				{
					code_units[0] = static_cast<T>(cp);
				}
				else
				{
					cp -= 0x10000u;
					code_units[0] = static_cast<T>(static_cast<uint16_t>(0xD800u | (cp >> 10)));	// high
					code_units[1] = static_cast<T>(static_cast<uint16_t>(0xDC00u | (cp & 0x3FFu))); // low
				}
			}

			MUU_NODISCARD_CTOR
			constexpr utf16_code_point(char32_t cp) noexcept // *** assumes cp is platform-endian ***
				: utf16_code_point{ static_cast<uint_least32_t>(cp) }
			{}

			MUU_NODISCARD
			constexpr std::basic_string_view<T> view() const noexcept
			{
				return code_units[1] ? std::basic_string_view<T>{ code_units, 2_sz }
									 : std::basic_string_view<T>{ code_units };
			}

			MUU_NODISCARD
			constexpr operator std::basic_string_view<T>() const noexcept
			{
				return view();
			}
		};

		MUU_ABI_VERSION_END;

		template <typename T, size_t S = sizeof(T)>
		struct utf_code_point_selector;
		template <typename T>
		struct utf_code_point_selector<T, 1>
		{
			using type = utf8_code_point<T>;
		};
		template <typename T>
		struct utf_code_point_selector<T, 2>
		{
			using type = utf16_code_point<T>;
		};
		template <typename T>
		struct utf_code_point_selector<T, 4>
		{
			using type = char32_t;
		};

		template <typename T>
		using utf_code_point = typename utf_code_point_selector<T>::type;

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr unsigned hex_to_dec(T codepoint) noexcept
		{
			if constexpr (std::is_same_v<remove_cvref<T>, unsigned>)
				return codepoint >= 0x41u					 // >= 'A'
						 ? 10u + (codepoint | 0x20u) - 0x61u // - 'a'
						 : codepoint - 0x30u				 // - '0'
					;
			else
				return hex_to_dec(static_cast<unsigned>(codepoint));
		}

		template <typename Char = char>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		constexpr Char dec_to_hex(unsigned val, Char a = constants<Char>::letter_a) noexcept
		{
			return static_cast<Char>(val >= 10u ? static_cast<unsigned>(a) + (val - 10u)
												: constants<Char>::digit_0 + val);
		}

		template <typename Char = char>
		struct hex_char_pair final
		{
			Char high;
			Char low;
		};

		template <typename Char, typename Traits>
		inline std::basic_ostream<Char, Traits>& operator<<(std::basic_ostream<Char, Traits>& lhs,
															hex_char_pair<Char> rhs)
		{
			static_assert(sizeof(hex_char_pair<Char>) == sizeof(Char) * 2);
			lhs.write(&rhs.high, 2u);
			return lhs;
		}

		template <typename Char = char>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr hex_char_pair<Char> byte_to_hex(uint8_t byte, Char a = constants<Char>::letter_a) noexcept
		{
			return { dec_to_hex(byte / 16u, a), dec_to_hex(byte % 16u, a) };
		}

		template <typename Char = char>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr hex_char_pair<Char> byte_to_hex(std::byte byte, Char a = constants<Char>::letter_a) noexcept
		{
			return byte_to_hex(unwrap(byte), a);
		}
	}
	/// \endcond

#endif // unicode/boilerplate

#if 1 // trim -----------------------------------------------------------------------------------------------------
	/// \addtogroup 	trim	trim()
	/// \brief Trims whitespace from both ends of a UTF string.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename T, typename Func>
		MUU_NODISCARD
		constexpr auto predicated_trim(std::basic_string_view<T> str, Func&& predicate) noexcept
			-> std::basic_string_view<T>
		{
			using view = std::basic_string_view<T>;

			if (str.empty())
				return view{};

			const auto first = utf_find(str, false, static_cast<Func&&>(predicate));
			if (!first)
				return view{};

			const auto last = utf_find(str, true, static_cast<Func&&>(predicate));

			return str.substr(first.index, last.end() - first.index);
		}
	}
	/// \endcond

	/// \brief		Trims whitespace from both ends of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::string_view trim(std::string_view str) noexcept
	{
		return impl::predicated_trim(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from both ends of a UTF wide string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::wstring_view trim(std::wstring_view str) noexcept
	{
		return impl::predicated_trim(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from both ends of a UTF-16 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u16string_view trim(std::u16string_view str) noexcept
	{
		return impl::predicated_trim(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from both ends of a UTF-32 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u32string_view trim(std::u32string_view str) noexcept
	{
		return impl::predicated_trim(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#ifdef __cpp_lib_char8_t

	/// \brief		Trims whitespace from both ends of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u8string_view trim(std::u8string_view str) noexcept
	{
		return impl::predicated_trim(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#endif // __cpp_lib_char8_t

	/** @} */ // strings::trim
#endif		  // trim

#if 1 // trim_left -----------------------------------------------------------------------------------------------------
	/// \addtogroup 	trim_left	trim_left()
	/// \brief Trims whitespace from the left end of a UTF string.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename T, typename Func>
		MUU_NODISCARD
		constexpr auto predicated_trim_left(std::basic_string_view<T> str, Func&& predicate) noexcept
			-> std::basic_string_view<T>
		{
			using view = std::basic_string_view<T>;

			if (str.empty())
				return view{};

			const auto first = utf_find(str, false, static_cast<Func&&>(predicate));
			if (!first)
				return view{};

			return str.substr(first.index);
		}
	}
	/// \endcond

	/// \brief		Trims whitespace from the left end of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::string_view trim_left(std::string_view str) noexcept
	{
		return impl::predicated_trim_left(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the left end of a UTF wide string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::wstring_view trim_left(std::wstring_view str) noexcept
	{
		return impl::predicated_trim_left(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the left end of a UTF-16 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u16string_view trim_left(std::u16string_view str) noexcept
	{
		return impl::predicated_trim_left(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the left end of a UTF-32 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u32string_view trim_left(std::u32string_view str) noexcept
	{
		return impl::predicated_trim_left(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#ifdef __cpp_lib_char8_t

	/// \brief		Trims whitespace from the left end of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u8string_view trim_left(std::u8string_view str) noexcept
	{
		return impl::predicated_trim_left(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#endif // __cpp_lib_char8_t

	/** @} */ // strings::trim_left
#endif		  // trim_left

#if 1 // trim_right ----------------------------------------------------------------------------------------------------
	/// \addtogroup 	trim_right	trim_right()
	/// \brief Trims whitespace from the right end of a UTF string.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename T, typename Func>
		MUU_NODISCARD
		constexpr auto predicated_trim_right(std::basic_string_view<T> str, Func&& predicate) noexcept
			-> std::basic_string_view<T>
		{
			using view = std::basic_string_view<T>;

			if (str.empty())
				return view{};

			const auto last = utf_find(str, true, static_cast<Func&&>(predicate));
			if (!last)
				return view{};

			return str.substr(0, last.end());
		}
	}
	/// \endcond

	/// \brief		Trims whitespace from the right end of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::string_view trim_right(std::string_view str) noexcept
	{
		return impl::predicated_trim_right(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the right end of a UTF wide string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::wstring_view trim_right(std::wstring_view str) noexcept
	{
		return impl::predicated_trim_right(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the right end of a UTF-16 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u16string_view trim_right(std::u16string_view str) noexcept
	{
		return impl::predicated_trim_right(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	/// \brief		Trims whitespace from the right end of a UTF-32 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u32string_view trim_right(std::u32string_view str) noexcept
	{
		return impl::predicated_trim_right(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#ifdef __cpp_lib_char8_t

	/// \brief		Trims whitespace from the right end of a UTF-8 string.
	MUU_NODISCARD
	MUU_ATTR(pure)
	constexpr std::u8string_view trim_right(std::u8string_view str) noexcept
	{
		return impl::predicated_trim_right(str, static_cast<bool (*)(char32_t) noexcept>(is_not_whitespace));
	}

	#endif // __cpp_lib_char8_t

	/** @} */ // strings::trim_right
#endif		  // trim_right

#if 1 // transcode -----------------------------------------------------------------------------------------------------
	/// \addtogroup 	transcode	transcode()
	/// \brief Transcodes a UTF string into another UTF encoding.
	/// @{

	/// \cond
	namespace impl
	{
		template <typename To, typename From>
		MUU_NODISCARD
		MUU_CONSTEXPR_STRING std::basic_string<To> utf_transcode(std::basic_string_view<From> str) noexcept
		{
			if (str.empty())
				return {};

			static_assert(is_code_unit<From> && is_code_unit<To>, "To and From must both be valid code unit types");

			if constexpr (std::is_same_v<To, From>)
				return std::basic_string<To>(str);
			else if constexpr (sizeof(To) == sizeof(From))
			{
				std::basic_string<To> out;
				out.resize(str.length());
				std::memcpy(out.data(), str.data(), str.length() * sizeof(From));
				return out;
			}
			else
			{
				std::basic_string<To> out;
				if constexpr (sizeof(To) < sizeof(From))
					out.reserve((str.length() / 2u) * 3u);
				else
					out.reserve(str.length());

				impl::utf_decode(str,
								 [&](char32_t cp) noexcept
								 {
									 if constexpr (std::is_same_v<char32_t, To>)
										 out += cp;
									 else if constexpr (sizeof(To) == sizeof(char32_t)) // e.g. wchar_t on linux
										 out += static_cast<To>(cp);
									 else
									 {
										 impl::utf_code_point<To> enc{ cp };
										 out.append(enc.view());
									 }
								 });

				return out;
			}
		}

	}
	/// \endcond

	/// \brief		Transcodes a UTF-8 string into another UTF encoding.
	template <typename Char>
	MUU_NODISCARD
	MUU_CONSTEXPR_STRING std::basic_string<Char> transcode(std::string_view str) noexcept
	{
		return impl::utf_transcode<Char>(str);
	}

	/// \brief		Transcodes a UTF wide string into another UTF encoding.
	template <typename Char>
	MUU_NODISCARD
	MUU_CONSTEXPR_STRING std::basic_string<Char> transcode(std::wstring_view str) noexcept
	{
		return impl::utf_transcode<Char>(str);
	}

	/// \brief		Transcodes a UTF-16 string into another UTF encoding.
	template <typename Char>
	MUU_NODISCARD
	MUU_CONSTEXPR_STRING std::basic_string<Char> transcode(std::u16string_view str) noexcept
	{
		return impl::utf_transcode<Char>(str);
	}

	/// \brief		Transcodes a UTF-32 string into another UTF encoding.
	template <typename Char>
	MUU_NODISCARD
	MUU_CONSTEXPR_STRING std::basic_string<Char> transcode(std::u32string_view str) noexcept
	{
		return impl::utf_transcode<Char>(str);
	}

	#ifdef __cpp_lib_char8_t
	/// \brief		Transcodes a UTF-8 string into another UTF encoding.
	template <typename Char>
	MUU_NODISCARD
	MUU_CONSTEXPR_STRING std::basic_string<Char> transcode(std::u8string_view str) noexcept
	{
		return impl::utf_transcode<Char>(str);
	}
	#endif // __cpp_lib_char8_t

	/** @} */ // strings::transcode
#endif		  // transcode

#if 1 // misc functions ------------------------------------------------------------------------------------------------

	/// \brief		Sets the name of the current thread for debuggers.
	MUU_API
	void set_thread_name(string_param name) noexcept;

#endif // misc functions

	/** @} */ // strings
}

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "impl/header_end.h"
