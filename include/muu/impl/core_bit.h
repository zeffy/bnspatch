// This file is a part of muu and is subject to the the terms of the MIT license.
// Copyright (c) Mark Gillard <mark.gillard@outlook.com.au>
// See https://github.com/marzer/muu/blob/master/LICENSE for the full license text.
// SPDX-License-Identifier: MIT

#pragma once
#include "core_utils.h"

MUU_DISABLE_WARNINGS;
#include <cstring> // memcpy
MUU_ENABLE_WARNINGS;

#include "header_start.h"
MUU_FORCE_NDEBUG_OPTIMIZATIONS; // these should be considered "intrinsics"
MUU_DISABLE_ARITHMETIC_WARNINGS;
MUU_PRAGMA_MSVC(warning(disable : 4191)) // unsafe pointer conversion

namespace muu
{
#if 1 // to make clang-format behave

	/// \cond
	namespace impl
	{
	#if 1

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr int MUU_VECTORCALL countl_zero_native(T val) noexcept
		{
			MUU_ASSUME(val > T{});

			using bit_type = largest<T, unsigned>;
			int count	   = 0;
			bit_type bit   = bit_type{ 1 } << (sizeof(T) * CHAR_BIT - 1);
			while (true)
			{
				if ((bit & val))
					break;
				count++;
				bit >>= 1;
			}
			return count;
		}

		#define MUU_HAS_INTRINSIC_COUNTL_ZERO 1

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_ATTR(flatten)
		int MUU_VECTORCALL countl_zero_intrinsic(T val) noexcept
		{
			MUU_ASSUME(val > T{});

		#if MUU_GCC || MUU_CLANG

			if constexpr (std::is_same_v<T, unsigned long long>)
				return __builtin_clzll(val);
			else if constexpr (std::is_same_v<T, unsigned long>)
				return __builtin_clzl(val);
			else if constexpr (std::is_same_v<T, unsigned int> || sizeof(T) == sizeof(unsigned int))
				return __builtin_clz(static_cast<unsigned int>(val));
			else if constexpr (sizeof(T) < sizeof(unsigned int))
				return __builtin_clz(val) - static_cast<int>((sizeof(unsigned int) - sizeof(T)) * CHAR_BIT);
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");

		#elif MUU_MSVC || MUU_ICC_CL

			if constexpr (sizeof(T) == sizeof(unsigned long long))
			{
			#if MUU_ARCH_X64

				unsigned long p;
				_BitScanReverse64(&p, static_cast<unsigned long long>(val));
				return 63 - static_cast<int>(p);

			#else

				if (const auto high = static_cast<unsigned long>(val >> 32); high != 0ull)
					return countl_zero_intrinsic(high);
				return 32 + countl_zero_intrinsic(static_cast<unsigned long>(val));

			#endif
			}
			else if constexpr (sizeof(T) == sizeof(unsigned long))
			{
				unsigned long p;
				_BitScanReverse(&p, static_cast<unsigned long>(val));
				return 31 - static_cast<int>(p);
			}
			else if constexpr (sizeof(T) < sizeof(unsigned long))
				return countl_zero_intrinsic(static_cast<unsigned long>(val))
					 - static_cast<int>((sizeof(unsigned long) - sizeof(T)) * CHAR_BIT);
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");

		#else

			#undef MUU_HAS_INTRINSIC_COUNTL_ZERO
			#define MUU_HAS_INTRINSIC_COUNTL_ZERO 0

			static_assert(always_false<T>, "countl_zero not implemented on this compiler");

		#endif
		}

	#endif
	}
	/// \endcond

	/// \brief	Counts the number of consecutive 0 bits, starting from the left.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::countl_zero, with the addition of also being
	/// 		 extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The value to test.
	///
	/// \returns	The number of consecutive zeros from the left end of an integer's bits.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr int MUU_VECTORCALL countl_zero(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return countl_zero(static_cast<std::underlying_type_t<T>>(val));

	#if MUU_HAS_INT128
		else if constexpr (std::is_same_v<T, uint128_t>)
		{
			if (const auto high = countl_zero(static_cast<uint64_t>(val >> 64)); high < 64)
				return high;
			else
				return 64 + countl_zero(static_cast<uint64_t>(val));
		}
	#endif

		else
		{
			if (!val)
				return static_cast<int>(sizeof(T) * CHAR_BIT);

			if constexpr (!build::supports_is_constant_evaluated || !MUU_HAS_INTRINSIC_COUNTL_ZERO)
				return impl::countl_zero_native(val);
			else
			{
				if (is_constant_evaluated())
					return impl::countl_zero_native(val);
				else
					return impl::countl_zero_intrinsic(val);
			}
		}
	}

	/// \cond
	namespace impl
	{
	#if 1

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr int MUU_VECTORCALL countr_zero_native(T val) noexcept
		{
			MUU_ASSUME(val > T{});

			using bit_type = largest<T, unsigned>;
			int count	   = 0;
			bit_type bit   = 1;
			while (true)
			{
				if ((bit & val))
					break;
				count++;
				bit <<= 1;
			}
			return count;
		}

		#define MUU_HAS_INTRINSIC_COUNTR_ZERO 1

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		MUU_ATTR(flatten)
		int MUU_VECTORCALL countr_zero_intrinsic(T val) noexcept
		{
			MUU_ASSUME(val > T{});

		#if MUU_GCC || MUU_CLANG

			if constexpr (std::is_same_v<T, unsigned long long>)
				return __builtin_ctzll(val);
			else if constexpr (std::is_same_v<T, unsigned long>)
				return __builtin_ctzl(val);
			else if constexpr (std::is_same_v<T, unsigned int> || sizeof(T) <= sizeof(unsigned int))
				return __builtin_ctz(val);
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");

		#elif MUU_MSVC || MUU_ICC_CL

			if constexpr (sizeof(T) == sizeof(unsigned long long))
			{
			#if MUU_ARCH_X64

				unsigned long p;
				_BitScanForward64(&p, static_cast<unsigned long long>(val));
				return static_cast<int>(p);

			#else

				if (const auto low = static_cast<unsigned long>(val); low != 0ull)
					return countr_zero_intrinsic(low);
				return 32 + countr_zero_intrinsic(static_cast<unsigned long>(val >> 32));

			#endif
			}
			else if constexpr (sizeof(T) == sizeof(unsigned long))
			{
				unsigned long p;
				_BitScanForward(&p, static_cast<unsigned long>(val));
				return static_cast<int>(p);
			}
			else if constexpr (sizeof(T) < sizeof(unsigned long))
				return countr_zero_intrinsic(static_cast<unsigned long>(val));
			else
				static_assert(always_false<T>, "Evaluated unreachable branch!");

		#else

			#undef MUU_HAS_INTRINSIC_COUNTR_ZERO
			#define MUU_HAS_INTRINSIC_COUNTR_ZERO 0

			static_assert(always_false<T>, "countr_zero not implemented on this compiler");

		#endif
		}

	#endif
	}
	/// \endcond

	/// \brief	Counts the number of consecutive 0 bits, starting from the right.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::countr_zero, with the addition of also being
	/// 		 extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The input value.
	///
	/// \returns	The number of consecutive zeros from the right end of an integer's bits.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr int MUU_VECTORCALL countr_zero(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return countr_zero(static_cast<std::underlying_type_t<T>>(val));

	#if MUU_HAS_INT128
		else if constexpr (std::is_same_v<T, uint128_t>)
		{
			if (const auto low = countr_zero(static_cast<uint64_t>(val)); low < 64)
				return low;
			else
				return 64 + countr_zero(static_cast<uint64_t>(val >> 64));
		}
	#endif

		else
		{
			if (!val)
				return static_cast<int>(sizeof(T) * CHAR_BIT);

			if constexpr (!build::supports_is_constant_evaluated || !MUU_HAS_INTRINSIC_COUNTR_ZERO)
				return impl::countr_zero_native(val);
			else
			{
				if (is_constant_evaluated())
					return impl::countr_zero_native(val);
				else
					return impl::countr_zero_intrinsic(val);
			}
		}
	}

	/// \brief	Counts the number of consecutive 1 bits, starting from the left.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::countl_one, with the addition of also being
	/// 		 extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The value to test.
	///
	/// \returns	The number of consecutive ones from the left end of an integer's bits.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr int MUU_VECTORCALL countl_one(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return countl_one(static_cast<std::underlying_type_t<T>>(val));
		else
			return countl_zero(static_cast<T>(~val));
	}

	/// \brief	Counts the number of consecutive 1 bits, starting from the right.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::countr_one, with the addition of also being
	/// 		 extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The value to test.
	///
	/// \returns	The number of consecutive ones from the right end of an integer's bits.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr int MUU_VECTORCALL countr_one(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return countr_one(static_cast<std::underlying_type_t<T>>(val));
		else
			return countr_zero(static_cast<T>(~val));
	}

	/// \brief	Finds the smallest integral power of two not less than the given value.
	/// \ingroup core
	///
	/// \remark This is equivalent to C++20's std::bit_ceil, with the addition of also being
	/// 		 extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The input value.
	///
	/// \returns	The smallest integral power of two that is not smaller than `val`.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T MUU_VECTORCALL bit_ceil(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return static_cast<T>(bit_ceil(static_cast<std::underlying_type_t<T>>(val)));
		else
		{
			if (!val)
				return T{ 1 };
			return T{ 1 } << (sizeof(T) * CHAR_BIT - static_cast<size_t>(countl_zero(static_cast<T>(val - T{ 1 }))));
		}
	}

	/// \brief	Bitwise-packs integers left-to-right into a larger integer.
	/// \ingroup core
	///
	/// \details \cpp
	/// auto   val1  = pack(0xAABB_u16, 0xCCDD_u16);
	/// assert(val1 == 0xAABBCCDD_u32);
	///
	/// auto   val2  = pack(0xAABB_u16, 0xCCDD_u16, 0xEEFF_u16);
	/// assert(val2 == 0x0000AABBCCDDEEFF_u64);
	///               // ^^^^ input was 48 bits, zero-padded to 64 on the left
	/// \ecpp
	///
	/// \tparam	Return	An integer or enum type,
	///			or leave as `void` to choose an unsigned type based on the total size of the inputs.
	/// \tparam	T	  	An integer or enum type.
	/// \tparam	U	  	An integer or enum type.
	/// \tparam	V	  	Integer or enum types.
	/// \param 	val1	The left-most value to be packed.
	/// \param 	val2	The second-left-most value to be packed.
	/// \param 	vals	Any remaining values to be packed.
	///
	/// \returns	An integral value containing the input values packed bitwise left-to-right. If the total size of the
	/// 			inputs was less than the return type, the output will be zero-padded on the left.
	MUU_CONSTRAINED_TEMPLATE((all_integral<T, U, V...>), typename Return = void, typename T, typename U, typename... V)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr auto MUU_VECTORCALL pack(T val1, U val2, V... vals) noexcept
	{
		static_assert(!is_cvref<Return>, "Return type cannot be const, volatile, or a reference");
		static_assert((total_size<T, U, V...> * CHAR_BIT) <= (MUU_HAS_INT128 ? 128 : 64),
					  "No integer type large enough to hold the packed values exists on the target platform");
		using return_type = std::conditional_t<std::is_void_v<Return>,
											   unsigned_integer<bit_ceil(total_size<T, U, V...> * CHAR_BIT)>,
											   Return>;
		static_assert(total_size<T, U, V...> <= sizeof(return_type), "Return type cannot fit all the input values");

		if constexpr (any_enum<return_type, T, U, V...>)
		{
			return static_cast<return_type>(
				pack<remove_enum<return_type>>(static_cast<std::underlying_type_t<T>>(val1),
											   static_cast<std::underlying_type_t<U>>(val2),
											   static_cast<std::underlying_type_t<V>>(vals)...));
		}
		else if constexpr (any_signed<return_type, T, U, V...>)
		{
			return static_cast<return_type>(pack<make_unsigned<return_type>>(static_cast<make_unsigned<T>>(val1),
																			 static_cast<make_unsigned<U>>(val2),
																			 static_cast<make_unsigned<V>>(vals)...));
		}
		else if constexpr (sizeof...(V) > 0)
		{
			return static_cast<return_type>(
				static_cast<return_type>(static_cast<return_type>(val1) << (total_size<U, V...> * CHAR_BIT))
				| pack<return_type>(val2, vals...));
		}
		else
		{
			return static_cast<return_type>(
				static_cast<return_type>(static_cast<return_type>(val1) << (sizeof(U) * CHAR_BIT))
				| static_cast<return_type>(val2));
		}
	}

	MUU_PUSH_WARNINGS;
	MUU_DISABLE_LIFETIME_WARNINGS;

	#define MUU_HAS_INTRINSIC_BIT_CAST 1

	/// \brief	Equivalent to C++20's std::bit_cast.
	/// \ingroup core
	///
	/// \remark Compilers implement this as an intrinsic which is typically
	/// 		 available regardless of the C++ mode. Using this function
	/// 		 on these compilers allows you to get the same behaviour
	/// 		 even when you aren't targeting C++20.
	///
	/// \availability On older compilers lacking support for std::bit_cast you won't be able to call this function
	/// 		   in constexpr contexts (since it falls back to a memcpy-based implementation).
	/// 		   You can check for constexpr support by examining build::supports_constexpr_bit_cast.
	template <typename To, typename From>
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(pure)
	MUU_ATTR(flatten)
	constexpr To bit_cast(const From& from) noexcept
	{
		static_assert(!std::is_reference_v<From> && !std::is_reference_v<To>, "From and To types cannot be references");
		static_assert(std::is_trivially_copyable_v<From> && std::is_trivially_copyable_v<To>,
					  "From and To types must be trivially-copyable");
		static_assert(sizeof(From) == sizeof(To), "From and To types must be the same size");

	#if MUU_CLANG >= 11 || MUU_GCC >= 11 || MUU_MSVC >= 1926

		return __builtin_bit_cast(To, from);

	#else

		#undef MUU_HAS_INTRINSIC_BIT_CAST
		#define MUU_HAS_INTRINSIC_BIT_CAST 0

		if constexpr (std::is_same_v<remove_cv<From>, remove_cv<To>>)
		{
			return from;
		}
		else if constexpr (all_integral<From, To>)
		{
			return static_cast<To>(
				static_cast<std::underlying_type_t<remove_cv<To>>>(static_cast<std::underlying_type_t<From>>(from)));
		}
		else
		{
			static_assert(std::is_nothrow_default_constructible_v<remove_cv<To>>,
						  "Bit-cast fallback requires the To type be nothrow default-constructible");

			remove_cv<To> dst;
			std::memcpy(&dst, &from, sizeof(To));
			return dst;
		}

	#endif
	}

	MUU_POP_WARNINGS;

	namespace build
	{
		/// \brief	True if using bit_cast() in constexpr contexts is supported on this compiler.
		inline constexpr bool supports_constexpr_bit_cast = !!MUU_HAS_INTRINSIC_BIT_CAST;
	}

	/// \cond
	namespace impl
	{
	#if 1
		template <size_t>
		struct popcount_traits;

		template <>
		struct popcount_traits<8>
		{
			static constexpr uint8_t m1	 = 0x55_u8;
			static constexpr uint8_t m2	 = 0x33_u8;
			static constexpr uint8_t m4	 = 0x0f_u8;
			static constexpr uint8_t h01 = 0x01_u8;
			static constexpr int rsh	 = 0;
		};

		template <>
		struct popcount_traits<16>
		{
			static constexpr uint16_t m1  = 0x5555_u16;
			static constexpr uint16_t m2  = 0x3333_u16;
			static constexpr uint16_t m4  = 0x0f0f_u16;
			static constexpr uint16_t h01 = 0x0101_u16;
			static constexpr int rsh	  = 8;
		};

		template <>
		struct popcount_traits<32>
		{
			static constexpr uint32_t m1  = 0x55555555_u32;
			static constexpr uint32_t m2  = 0x33333333_u32;
			static constexpr uint32_t m4  = 0x0f0f0f0f_u32;
			static constexpr uint32_t h01 = 0x01010101_u32;
			static constexpr int rsh	  = 24;
		};

		template <>
		struct popcount_traits<64>
		{
			static constexpr uint64_t m1  = 0x5555555555555555_u64;
			static constexpr uint64_t m2  = 0x3333333333333333_u64;
			static constexpr uint64_t m4  = 0x0f0f0f0f0f0f0f0f_u64;
			static constexpr uint64_t h01 = 0x0101010101010101_u64;
			static constexpr int rsh	  = 56;
		};

		#if MUU_HAS_INT128
		template <>
		struct popcount_traits<128>
		{
			static constexpr uint128_t m1  = pack(0x5555555555555555_u64, 0x5555555555555555_u64);
			static constexpr uint128_t m2  = pack(0x3333333333333333_u64, 0x3333333333333333_u64);
			static constexpr uint128_t m4  = pack(0x0f0f0f0f0f0f0f0f_u64, 0x0f0f0f0f0f0f0f0f_u64);
			static constexpr uint128_t h01 = pack(0x0101010101010101_u64, 0x0101010101010101_u64);
			static constexpr int rsh	   = 120;
		};
		#endif

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr int MUU_VECTORCALL popcount_native(T val) noexcept
		{
			MUU_ASSUME(val > T{});

			using pt = popcount_traits<sizeof(T) * CHAR_BIT>;
			val -= ((val >> 1) & pt::m1);
			val = static_cast<T>((val & pt::m2) + ((val >> 2) & pt::m2));
			return static_cast<int>(static_cast<T>(((val + (val >> 4)) & pt::m4) * pt::h01) >> pt::rsh);
		}

		#define MUU_HAS_INTRINSIC_POPCOUNT 1

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		auto MUU_VECTORCALL popcount_intrinsic(T val) noexcept
		{
			MUU_ASSUME(val > T{});

		#if MUU_GCC || MUU_CLANG

			if constexpr (sizeof(T) <= sizeof(unsigned int))
				return __builtin_popcount(static_cast<unsigned int>(val));
			else if constexpr (std::is_same_v<T, unsigned long>)
				return __builtin_popcountl(val);
			else if constexpr (std::is_same_v<T, unsigned long long>)
				return __builtin_popcountll(val);
			#if MUU_HAS_INT128
			else if constexpr (std::is_same_v<T, uint128_t>)
				return __builtin_popcountll(static_cast<unsigned long long>(val >> 64))
					 + __builtin_popcountll(static_cast<unsigned long long>(val));
			#endif
			else
				static_assert(always_false<T>, "Unsupported integer type");

		#elif MUU_ICC

			if constexpr (sizeof(T) <= sizeof(int))
				return _popcnt32(static_cast<int>(val));
			else if constexpr (sizeof(T) == sizeof(__int64))
				return _popcnt64(static_cast<__int64>(val));
			else
				static_assert(always_false<T>, "Unsupported integer type");

		#elif MUU_MSVC

			if constexpr (sizeof(T) <= sizeof(unsigned short))
			{
			#if MUU_MSVC >= 1928 // VS 16.8
				return __popcnt16(static_cast<unsigned short>(val));
			#else
				return popcount_native(val);
			#endif
			}
			else if constexpr (sizeof(T) == sizeof(unsigned int))
				return __popcnt(static_cast<unsigned int>(val));
			else if constexpr (std::is_same_v<T, unsigned __int64>)
			{
			#if MUU_MSVC >= 1928 && MUU_ARCH_X64 // VS 16.8
				return __popcnt64(static_cast<unsigned __int64>(val));
			#else
				return __popcnt(static_cast<unsigned int>(val >> 32)) + __popcnt(static_cast<unsigned int>(val));
			#endif
			}
			else
				static_assert(always_false<T>, "Unsupported integer type");

		#else

			#undef MUU_HAS_INTRINSIC_POPCOUNT
			#define MUU_HAS_INTRINSIC_POPCOUNT 0

			static_assert(always_false<T>, "popcount_intrinsic not implemented for this compiler");

		#endif
		}

	#endif
	}
	/// \endcond

	/// \brief	Counts the number of set bits (the 'population count') of an unsigned integer.
	/// \ingroup core
	///
	/// \remark	This is equivalent to C++20's std::popcount, with the addition of also being
	/// 		extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The input value.
	///
	/// \returns	The number of bits that were set to `1` in `val`.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr int MUU_VECTORCALL popcount(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return popcount(static_cast<std::underlying_type_t<T>>(val));
		else
		{
			if (!val)
				return 0;

			if constexpr (!build::supports_is_constant_evaluated || !MUU_HAS_INTRINSIC_POPCOUNT)
				return impl::popcount_native(val);
			else
			{
				if (is_constant_evaluated())
					return impl::popcount_native(val);
				else
					return static_cast<int>(impl::popcount_intrinsic(val));
			}
		}
	}

	/// \brief	Checks if an integral value has only a single bit set.
	/// \ingroup core
	///
	/// \remark	This is equivalent to C++20's std::has_single_bit, with the addition of also being
	/// 		extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The value to test.
	///
	/// \returns	True if the input value had only a single bit set (and thus was a power of two).
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr bool MUU_VECTORCALL has_single_bit(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return has_single_bit(static_cast<std::underlying_type_t<T>>(val));
		else
		{
			if constexpr (!build::supports_is_constant_evaluated || !MUU_HAS_INTRINSIC_POPCOUNT)
				return val != T{} && (val & (val - T{ 1 })) == T{};
			else
			{
				if (is_constant_evaluated())
					return val != T{} && (val & (val - T{ 1 })) == T{};
				else
					return impl::popcount_intrinsic(val) == 1;
			}
		}
	}

	/// \brief	Finds the largest integral power of two not greater than the given value.
	/// \ingroup core
	///
	/// \remark	This is equivalent to C++20's std::bit_floor, with the addition of also being
	/// 		extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The input value.
	///
	/// \returns	Zero if `val` is zero; otherwise, the largest integral power of two that is not greater than `val`.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T MUU_VECTORCALL bit_floor(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return static_cast<T>(bit_floor(static_cast<std::underlying_type_t<T>>(val)));
		else
		{
			if (!val)
				return T{ 0 };
			return T{ 1 } << (sizeof(T) * CHAR_BIT - 1_sz - static_cast<size_t>(countl_zero(val)));
		}
	}

	/// \brief	Finds the smallest number of bits needed to represent the given value.
	/// \ingroup core
	///
	/// \remark	This is equivalent to C++20's std::bit_width, with the addition of also being
	/// 		extended to work with enum types.
	///
	/// \tparam	T		An unsigned integer or enum type.
	/// \param 	val		The input value.
	///
	/// \returns	If `val` is not zero, calculates the number of bits needed to store `val` (i.e. `1 + log2(x)`).
	/// 			Returns `0` if `val` is zero.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T MUU_VECTORCALL bit_width(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return static_cast<T>(bit_width(static_cast<std::underlying_type_t<T>>(val)));
		else
			return static_cast<T>(sizeof(T) * CHAR_BIT - static_cast<size_t>(countl_zero(val)));
	}

	/// \brief	Returns an unsigned integer filled from the right
	/// 		with the desired number of consecutive ones.
	/// \ingroup core
	///
	/// \details \cpp
	/// const auto val1 = bit_fill_right<uint32_t>(5);
	/// const auto val2 = 0b00000000000000000000000000011111u;
	/// assert(val1 == val2);
	///  \ecpp
	///
	/// \tparam	T		An unsigned integer type.
	/// \param 	count	Number of consecutive ones.
	///
	/// \returns	An instance of T right-filled with the desired number of ones.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T MUU_VECTORCALL bit_fill_right(size_t count) noexcept
	{
		if constexpr (is_enum<T>)
			return T{ bit_fill_right<remove_enum<remove_cvref<T>>>(count) };
		else
		{
			if (!count)
				return T{};
			if (count >= build::bits_per_byte * sizeof(T))
				return static_cast<T>(~T{});
			return static_cast<T>((T{ 1 } << count) - T{ 1 });
		}
	}

	/// \brief	Returns an unsigned integer filled from the left
	/// 		with the desired number of consecutive ones.
	/// \ingroup core
	///
	/// \details \cpp
	/// const auto val1 = bit_fill_left<uint32_t>(5);
	/// const auto val2 = 0b11111000000000000000000000000000u;
	/// assert(val1 == val2);
	///  \ecpp
	///
	/// \tparam	T		An unsigned integer type.
	/// \param 	count	Number of consecutive ones.
	///
	/// \returns	An instance of T left-filled with the desired number of ones.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	constexpr T MUU_VECTORCALL bit_fill_left(size_t count) noexcept
	{
		if constexpr (is_enum<T>)
			return T{ bit_fill_left<remove_enum<remove_cvref<T>>>(count) };
		else
		{
			if (!count)
				return T{};
			if (count >= build::bits_per_byte * sizeof(T))
				return static_cast<T>(~T{});
			return static_cast<T>(bit_fill_right<T>(count) << (build::bits_per_byte * sizeof(T) - count));
		}
	}

	/// \brief	Gets a specific byte from an integer.
	/// \ingroup core
	///
	/// \details \cpp
	/// const auto i = 0xAABBCCDDu;
	/// //                ^ ^ ^ ^
	/// // byte indices:  3 2 1 0
	///
	/// std::cout << std::hex;
	///	std::cout << "0: " << byte_select<0>(i) << "\n";
	///	std::cout << "1: " << byte_select<1>(i) << "\n";
	///	std::cout << "2: " << byte_select<2>(i) << "\n";
	///	std::cout << "3: " << byte_select<3>(i) << "\n";
	/// \ecpp
	///
	/// \out
	/// 0: DD
	/// 1: CC
	/// 2: BB
	/// 3: AA
	/// (on a little-endian system)
	/// \eout
	///
	/// \tparam	Index	Index of the byte to retrieve.
	/// \tparam	T		An integer or enum type.
	/// \param 	val		An integer or enum value.
	///
	/// \remark The indexation order of bytes is the _memory_ order, not their
	/// 		 numeric significance (i.e. byte 0 is always the first byte in the integer's
	/// 		 memory allocation, regardless of the endianness of the platform).
	///
	/// \returns	The value of the selected byte.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, size_t Index, typename T)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr uint8_t MUU_VECTORCALL byte_select(T val) noexcept
	{
		static_assert(Index < sizeof(T),
					  "The byte index is out-of-range; it must be less than the size of the input integer");

		if constexpr (is_enum<T>)
			return byte_select<Index>(static_cast<std::underlying_type_t<T>>(val));
		else if constexpr (is_signed<T>)
			return byte_select<Index>(static_cast<make_unsigned<T>>(val));
		else if constexpr (sizeof(T) == 1_sz)
			return static_cast<uint8_t>(val);
		else
		{
			constexpr auto mask = static_cast<T>(0xFFu) << (Index * CHAR_BIT);
			if constexpr (Index == 0_sz)
				return static_cast<uint8_t>(mask & static_cast<T>(val));
			else
				return static_cast<uint8_t>((mask & static_cast<T>(val)) >> (Index * CHAR_BIT));
		}
	}

	/// \brief	Gets a specific byte from an integer.
	/// \ingroup core
	///
	/// \details \cpp
	/// const auto i = 0xAABBCCDDu;
	/// //                ^ ^ ^ ^
	/// // byte indices:  3 2 1 0
	///
	/// std::cout << std::hex;
	///	std::cout << "0: " << byte_select(i, 0) << "\n";
	///	std::cout << "1: " << byte_select(i, 1) << "\n";
	///	std::cout << "2: " << byte_select(i, 2) << "\n";
	///	std::cout << "3: " << byte_select(i, 3) << "\n";
	/// \ecpp
	///
	/// \out
	/// 0: DD
	/// 1: CC
	/// 2: BB
	/// 3: AA
	/// (on a little-endian system)
	/// \eout
	///
	/// \tparam	T		An integer or enum type.
	/// \param 	val		An integer or enum value.
	/// \param	index	Index of the byte to retrieve.
	///
	/// \remark The indexation order of bytes is the _memory_ order, not their
	/// 		 numeric significance (i.e. byte 0 is always the first byte in the integer's
	/// 		 memory allocation, regardless of the endianness of the platform).
	///
	/// \returns	The value of the selected byte, or 0 if the index was out-of-range.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, typename T)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr uint8_t MUU_VECTORCALL byte_select(T val, size_t index) noexcept
	{
		if (index > sizeof(T))
			return uint8_t{};

		if constexpr (is_enum<T>)
			return byte_select(static_cast<std::underlying_type_t<T>>(val), index);
		else if constexpr (is_signed<T>)
			return byte_select(static_cast<make_unsigned<T>>(val), index);
		else if constexpr (sizeof(T) == 1_sz)
			return static_cast<uint8_t>(val);
		else
			return static_cast<uint8_t>(static_cast<T>(val >> (index * CHAR_BIT)) & static_cast<T>(0xFFu));
	}

	/// \cond
	namespace impl
	{
	#if 1

		#define MUU_HAS_INTRINSIC_BYTE_REVERSE 1

		template <typename T>
		MUU_NODISCARD
		MUU_ALWAYS_INLINE
		MUU_ATTR(const)
		T MUU_VECTORCALL byte_reverse_intrinsic(T val) noexcept
		{
		#if MUU_GCC || MUU_CLANG

			if constexpr (std::is_same_v<T, uint16_t>)
				return __builtin_bswap16(val);
			else if constexpr (std::is_same_v<T, uint32_t>)
				return __builtin_bswap32(val);
			else if constexpr (std::is_same_v<T, uint64_t>)
				return __builtin_bswap64(val);
			#if MUU_HAS_INT128
			else if constexpr (std::is_same_v<T, uint128_t>)
			{
				#if MUU_HAS_BUILTIN(__builtin_bswap128)
				return __builtin_bswap128(val);
				#else
				return (static_cast<uint128_t>(byte_reverse_intrinsic(static_cast<uint64_t>(val))) << 64)
					 | byte_reverse_intrinsic(static_cast<uint64_t>(val >> 64));
				#endif
			}
			#endif
			else
				static_assert(always_false<T>, "Unsupported integer type");

		#elif MUU_MSVC || MUU_ICC_CL

			if constexpr (sizeof(T) == sizeof(unsigned short))
				return static_cast<T>(_byteswap_ushort(static_cast<unsigned short>(val)));
			else if constexpr (sizeof(T) == sizeof(unsigned long))
				return static_cast<T>(_byteswap_ulong(static_cast<unsigned long>(val)));
			else if constexpr (sizeof(T) == sizeof(unsigned long long))
				return static_cast<T>(_byteswap_uint64(static_cast<unsigned long long>(val)));
			else
				static_assert(always_false<T>, "Unsupported integer type");

		#else

			#undef MUU_HAS_INTRINSIC_BYTE_REVERSE
			#define MUU_HAS_INTRINSIC_BYTE_REVERSE 0

			static_assert(always_false<T>, "byte_reverse_intrinsic not implemented for this compiler");

		#endif
		}

		template <typename T>
		MUU_NODISCARD
		MUU_ATTR(const)
		constexpr T MUU_VECTORCALL byte_reverse_native(T val) noexcept
		{
			if constexpr (sizeof(T) == sizeof(uint16_t))
			{
				return static_cast<T>(static_cast<uint32_t>(val << 8) | static_cast<uint32_t>(val >> 8));
			}
			else if constexpr (sizeof(T) == sizeof(uint32_t))
			{
				return (val << 24) | ((val << 8) & 0x00FF0000_u32) | ((val >> 8) & 0x0000FF00_u32) | (val >> 24);
			}
			else if constexpr (sizeof(T) == sizeof(uint64_t))
			{
				return (val << 56) | ((val << 40) & 0x00FF000000000000_u64) | ((val << 24) & 0x0000FF0000000000_u64)
					 | ((val << 8) & 0x000000FF00000000_u64) | ((val >> 8) & 0x00000000FF000000_u64)
					 | ((val >> 24) & 0x0000000000FF0000_u64) | ((val >> 40) & 0x000000000000FF00_u64) | (val >> 56);
			}
		#if MUU_HAS_INT128
			else if constexpr (sizeof(T) == sizeof(uint128_t))
			{
				return (static_cast<uint128_t>(byte_reverse_native(static_cast<uint64_t>(val))) << 64)
					 | byte_reverse_native(static_cast<uint64_t>(val >> 64));
			}
		#endif
			else
				static_assert(always_false<T>, "Unsupported integer type");
		}

	#endif
	}
	/// \endcond

	/// \brief	Reverses the byte order of an unsigned integral type.
	/// \ingroup core
	///
	/// \details \cpp
	/// const auto i = 0xAABBCCDDu;
	/// const auto j = byte_reverse(i);
	/// std::cout << std::hex << i << "\n" << j;
	/// \ecpp
	///
	/// \out
	/// AABBCCDD
	/// DDCCBBAA
	/// \eout
	///
	/// \tparam	T	An unsigned integer or enum type.
	/// \param 	val	An unsigned integer or enum value.
	///
	/// \returns	A copy of the input value with the byte order reversed.
	MUU_CONSTRAINED_TEMPLATE(is_unsigned<T>, typename T)
	MUU_NODISCARD
	MUU_ALWAYS_INLINE
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr T MUU_VECTORCALL byte_reverse(T val) noexcept
	{
		if constexpr (is_enum<T>)
			return static_cast<T>(byte_reverse(static_cast<std::underlying_type_t<T>>(val)));
		else
		{
			if constexpr (!build::supports_is_constant_evaluated || !MUU_HAS_INTRINSIC_BYTE_REVERSE)
				return impl::byte_reverse_native(val);
			else
			{
				if (is_constant_evaluated())
					return impl::byte_reverse_native(val);
				else
					return impl::byte_reverse_intrinsic(val);
			}
		}
	}

	/// \brief	Select and re-pack arbitrary bytes from an integer.
	/// \ingroup core
	///
	/// \details \cpp
	///
	/// const auto i = 0xAABBCCDDu;
	/// //                ^ ^ ^ ^
	/// // byte indices:  3 2 1 0
	///
	/// std::cout << std::hex << std::setfill('0');
	///	std::cout << "      <0>: " << std::setw(8) <<       swizzle<0>(i) << "\n";
	///	std::cout << "   <1, 0>: " << std::setw(8) <<    swizzle<1, 0>(i) << "\n";
	///	std::cout << "<3, 2, 3>: " << std::setw(8) << swizzle<3, 2, 3>(i) << "\n";
	/// \ecpp
	///
	/// \out
	///       <0>: 000000DD
	///    <1, 0>: 0000CCDD
	/// <3, 2, 3>: 00AABBAA
	/// (on a little-endian system)
	/// \eout
	///
	/// \tparam	ByteIndices		Indices of the bytes from the source integer in the (little-endian) order they're to be packed.
	/// \tparam	T				An integer or enum type.
	/// \param	val				An integer or enum value.
	///
	/// \remark The indexation order of bytes is the _memory_ order, not their
	/// 		 numeric significance (i.e. byte 0 is always the first byte in the integer's
	/// 		 memory allocation, regardless of the endianness of the platform).
	///
	/// \returns	An integral value containing the selected bytes packed bitwise left-to-right. If the total size of the
	/// 			inputs was less than the return type, the output will be zero-padded on the left.
	MUU_CONSTRAINED_TEMPLATE(is_integral<T>, size_t... ByteIndices, typename T)
	MUU_NODISCARD
	MUU_ATTR(const)
	MUU_ATTR(flatten)
	constexpr auto MUU_VECTORCALL swizzle(T val) noexcept
	{
		static_assert(sizeof...(ByteIndices) > 0_sz, "At least one byte index must be specified.");
		static_assert((sizeof...(ByteIndices) * CHAR_BIT) <= (MUU_HAS_INT128 ? 128 : 64),
					  "No integer type large enough to hold the swizzled value exists on the target platform");
		static_assert((true && ... && (ByteIndices < sizeof(T))),
					  "One or more of the source byte indices was out-of-range");
		using swizzle_type = std::conditional_t<is_signed<T>,
												signed_integer<bit_ceil(sizeof...(ByteIndices) * CHAR_BIT)>,
												unsigned_integer<bit_ceil(sizeof...(ByteIndices) * CHAR_BIT)>>;
		using return_type  = std::conditional_t<sizeof...(ByteIndices) == sizeof(T), T, swizzle_type>;

		if constexpr (is_enum<T>)
			return static_cast<return_type>(swizzle<ByteIndices...>(static_cast<std::underlying_type_t<T>>(val)));
		else if constexpr (is_signed<T>)
			return static_cast<return_type>(swizzle<ByteIndices...>(static_cast<make_unsigned<T>>(val)));
		else if constexpr (sizeof...(ByteIndices) == 1_sz)
			return static_cast<return_type>(byte_select<ByteIndices...>(val));
		else
			return pack<return_type>(byte_select<ByteIndices>(val)...);
	}

#endif
}

#undef MUU_HAS_INTRINSIC_BIT_CAST
#undef MUU_HAS_INTRINSIC_POPCOUNT
#undef MUU_HAS_INTRINSIC_BYTE_REVERSE
#undef MUU_HAS_INTRINSIC_COUNTL_ZERO
#undef MUU_HAS_INTRINSIC_COUNTR_ZERO

MUU_RESET_NDEBUG_OPTIMIZATIONS;
#include "header_end.h"
